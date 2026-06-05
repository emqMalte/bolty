package cmd

import (
	"bufio"
	"context"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type configureOptions struct {
	ProfileName             string
	AccountKitPath          string
	ServerURL               string
	UserID                  string
	PrivateKeyPath          string
	Passphrase              string
	TOTP                    string
	AcceptServerFingerprint string
	SetDefault              bool
}

var configureCmd = &cobra.Command{
	Use:          "configure [profile]",
	Short:        "Configure Passbolt access",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		profileName := passbolt.DefaultProfileName
		if len(args) == 1 {
			profileName = args[0]
		}
		opts, err := configureOptionsFromCommand(cmd, profileName)
		if err != nil {
			return err
		}
		return runConfigure(cmd, opts)
	},
}

func init() {
	rootCmd.AddCommand(configureCmd)
	addConfigureFlags(configureCmd)
}

func addConfigureFlags(cmd *cobra.Command) {
	cmd.Flags().String("account-kit", "", "Passbolt account kit file")
	cmd.Flags().String("server-url", "", "Passbolt server base URL")
	cmd.Flags().String("user-id", "", "Passbolt user ID")
	cmd.Flags().String("private-key", "", "Path to armored private key")
	cmd.Flags().String("totp", "", "TOTP code for MFA")
	cmd.Flags().String("accept-server-fingerprint", "", "Expected Passbolt server public key fingerprint")
	cmd.Flags().Bool("set-default", false, "Set this profile as default")
	addPassphraseEnvFlag(cmd)
}

func configureOptionsFromCommand(cmd *cobra.Command, profileName string) (configureOptions, error) {
	passphrase, _, err := passphraseFromEnvFlag(cmd)
	if err != nil {
		return configureOptions{}, err
	}
	accountKitPath, _ := cmd.Flags().GetString("account-kit")
	serverURL, _ := cmd.Flags().GetString("server-url")
	userID, _ := cmd.Flags().GetString("user-id")
	privateKeyPath, _ := cmd.Flags().GetString("private-key")
	totp, _ := cmd.Flags().GetString("totp")
	accepted, _ := cmd.Flags().GetString("accept-server-fingerprint")
	setDefault, _ := cmd.Flags().GetBool("set-default")
	return configureOptions{
		ProfileName:             profileName,
		AccountKitPath:          accountKitPath,
		ServerURL:               serverURL,
		UserID:                  userID,
		PrivateKeyPath:          privateKeyPath,
		Passphrase:              passphrase,
		TOTP:                    totp,
		AcceptServerFingerprint: accepted,
		SetDefault:              setDefault,
	}, nil
}

func runConfigure(cmd *cobra.Command, opts configureOptions) error {
	profile, privateKey, err := profileMaterial(opts)
	if err != nil {
		return err
	}
	if opts.Passphrase == "" {
		opts.Passphrase, err = readSecret(cmd, "Private key passphrase: ")
		if err != nil {
			return err
		}
	}

	serverKey, fingerprint, err := fetchServerPublicKey(cmd.Context(), profile.ServerURL, passboltClientOptions()...)
	if err != nil {
		return err
	}
	if err := confirmServerFingerprint(cmd, fingerprint, opts.AcceptServerFingerprint); err != nil {
		return err
	}
	if err := verifyPrivateKeyMatchesServer(privateKey, opts.Passphrase, serverKey); err != nil {
		return err
	}
	if err := verifyLogin(cmd.Context(), profile, privateKey, opts.Passphrase, opts.TOTP); err != nil {
		return err
	}

	configStore := passbolt.NewConfigStore(viper.GetViper())
	if err := configStore.UpsertProfile(profile, opts.SetDefault); err != nil {
		return err
	}
	secretStore := passbolt.NewOSKeyringStore()
	if err := secretStore.Set(profile.Name, passbolt.SecretPrivateKey, privateKey); err != nil {
		return err
	}
	if err := secretStore.Set(profile.Name, passbolt.SecretPrivateKeyPass, opts.Passphrase); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Profile %q configured\n", profile.Name)
	return nil
}

func profileMaterial(opts configureOptions) (passbolt.Profile, string, error) {
	profileName := strings.TrimSpace(opts.ProfileName)
	if profileName == "" {
		profileName = passbolt.DefaultProfileName
	}
	if opts.AccountKitPath != "" {
		if opts.ServerURL != "" || opts.UserID != "" || opts.PrivateKeyPath != "" {
			return passbolt.Profile{}, "", fmt.Errorf("use either --account-kit or manual settings (--server-url, --user-id, --private-key), not both")
		}
		kit, err := passbolt.ParseAccountKitFile(opts.AccountKitPath)
		if err != nil {
			return passbolt.Profile{}, "", fmt.Errorf("read account kit %q: %w", opts.AccountKitPath, err)
		}
		return passbolt.Profile{
			Name:      profileName,
			ServerURL: kit.ServerURL,
			UserID:    kit.UserID,
			Username:  kit.Username,
		}, kit.PrivateKey, nil
	}
	if opts.ServerURL == "" || opts.UserID == "" || opts.PrivateKeyPath == "" {
		return passbolt.Profile{}, "", fmt.Errorf("missing profile source: pass --account-kit <path>, or pass all manual settings: --server-url <url> --user-id <uuid> --private-key <path>")
	}
	keyData, err := os.ReadFile(opts.PrivateKeyPath)
	if err != nil {
		return passbolt.Profile{}, "", fmt.Errorf("read private key %q: %w", opts.PrivateKeyPath, err)
	}
	return passbolt.Profile{
		Name:      profileName,
		ServerURL: opts.ServerURL,
		UserID:    opts.UserID,
	}, string(keyData), nil
}

func fetchServerPublicKey(ctx context.Context, serverURL string, opts ...passbolt.Option) (*crypto.Key, string, error) {
	client, err := passbolt.NewClient(serverURL, opts...)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.ViewAuthVerifyWithResponse(ctx)
	if err != nil {
		return nil, "", err
	}
	if resp.JSON200 == nil {
		return nil, "", fmt.Errorf("fetch Passbolt server public key: status %s body %s", resp.Status(), string(resp.Body))
	}
	body := resp.JSON200.Body
	key, err := passbolt.NewPGPService().PublicKey(body.Keydata)
	if err != nil {
		return nil, "", fmt.Errorf("parse server public key: %w", err)
	}
	actual := normalizeFingerprint(key.GetFingerprint())
	reported := normalizeFingerprint(body.Fingerprint)
	if reported != "" && subtle.ConstantTimeCompare([]byte(actual), []byte(reported)) != 1 {
		return nil, "", fmt.Errorf("server fingerprint mismatch: API reported %s but keydata has %s", reported, actual)
	}
	return key, actual, nil
}

func confirmServerFingerprint(cmd *cobra.Command, actual, accepted string) error {
	actual = normalizeFingerprint(actual)
	accepted = normalizeFingerprint(accepted)
	if accepted != "" {
		if subtle.ConstantTimeCompare([]byte(actual), []byte(accepted)) != 1 {
			return fmt.Errorf("server fingerprint mismatch: expected %s, got %s", accepted, actual)
		}
		return nil
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Passbolt server public key fingerprint: %s\n", actual)
	fmt.Fprint(cmd.ErrOrStderr(), "Trust this server key? [y/N]: ")
	answer, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil {
		return err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return fmt.Errorf("server fingerprint was not accepted")
	}
	return nil
}

func verifyPrivateKeyMatchesServer(privateKey, passphrase string, serverKey *crypto.Key) error {
	unlocked, err := passbolt.NewPGPService().UnlockPrivateKey(privateKey, passphrase)
	if err != nil {
		return fmt.Errorf("unlock private key: %w", err)
	}
	defer unlocked.ClearPrivateParams()
	if _, err := passbolt.NewPGPService().EncryptAndSign([]byte("bolty configure verification"), serverKey, unlocked); err != nil {
		return fmt.Errorf("verify private key can sign Passbolt challenge: %w", err)
	}
	return nil
}

func verifyLogin(ctx context.Context, profile passbolt.Profile, privateKey, passphrase, totp string) error {
	store := newCommandMemorySecretStore()
	if err := store.Set(profile.Name, passbolt.SecretPrivateKey, privateKey); err != nil {
		return err
	}
	if err := store.Set(profile.Name, passbolt.SecretPrivateKeyPass, passphrase); err != nil {
		return err
	}
	auth := passbolt.NewAuthService(store)
	if _, err := auth.Login(ctx, profile, totp, passboltClientOptions()...); err != nil {
		return fmt.Errorf("verify Passbolt login: %w", err)
	}
	return nil
}

func normalizeFingerprint(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "", ":", "", "-", "")
	return replacer.Replace(value)
}

type commandMemorySecretStore struct {
	values map[string]string
}

func newCommandMemorySecretStore() *commandMemorySecretStore {
	return &commandMemorySecretStore{values: map[string]string{}}
}

func (s *commandMemorySecretStore) Set(profile, name, value string) error {
	s.values[profile+"\x00"+name] = value
	return nil
}

func (s *commandMemorySecretStore) Get(profile, name string) (string, error) {
	value, ok := s.values[profile+"\x00"+name]
	if !ok {
		return "", passbolt.ErrSecretNotFound
	}
	return value, nil
}

func (s *commandMemorySecretStore) Delete(profile, name string) error {
	key := profile + "\x00" + name
	if _, ok := s.values[key]; !ok {
		return passbolt.ErrSecretNotFound
	}
	delete(s.values, key)
	return nil
}

func (s *commandMemorySecretStore) DeleteProfile(profile string) error {
	prefix := profile + "\x00"
	for key := range s.values {
		if strings.HasPrefix(key, prefix) {
			delete(s.values, key)
		}
	}
	return nil
}
