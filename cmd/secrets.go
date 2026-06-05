package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func addPassphraseEnvFlag(cmd *cobra.Command) {
	cmd.Flags().String("passphrase-env", "", "Environment variable containing the private key passphrase")
}

func passphraseFromEnvFlag(cmd *cobra.Command) (string, bool, error) {
	envName, err := cmd.Flags().GetString("passphrase-env")
	if err != nil {
		return "", false, err
	}
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return "", false, nil
	}
	value := os.Getenv(envName)
	if value == "" {
		return "", false, fmt.Errorf("environment variable %s is empty or not set", envName)
	}
	return value, true, nil
}

func authServiceFromCommand(cmd *cobra.Command, store passbolt.SecretStore) (passbolt.AuthService, error) {
	passphrase, ok, err := passphraseFromEnvFlag(cmd)
	if err != nil {
		return passbolt.AuthService{}, err
	}
	auth := passbolt.NewAuthService(store)
	if ok {
		auth.PassphraseOverride = passphrase
	}
	return auth, nil
}

func readSecret(cmd *cobra.Command, prompt string) (string, error) {
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	value, err := term.ReadPassword(0)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	return string(value), nil
}
