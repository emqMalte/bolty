package cmd

import (
	"context"
	"fmt"

	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to Passbolt with JWT authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		profile, err := passbolt.NewConfigStore(viper.GetViper()).GetProfile(viper.GetString("profile"))
		if err != nil {
			return err
		}
		totp, _ := cmd.Flags().GetString("totp")
		auth, err := authServiceFromCommand(cmd, passbolt.NewOSKeyringStore())
		if err != nil {
			return err
		}
		if _, err := auth.Login(context.Background(), profile, totp, passboltClientOptions()...); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Logged in as profile %q\n", profile.Name)
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from Passbolt",
	RunE: func(cmd *cobra.Command, args []string) error {
		profile, err := passbolt.NewConfigStore(viper.GetViper()).GetProfile(viper.GetString("profile"))
		if err != nil {
			return err
		}
		auth := passbolt.NewAuthService(passbolt.NewOSKeyringStore())
		if err := auth.Logout(context.Background(), profile, passboltClientOptions()...); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Logged out profile %q\n", profile.Name)
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check Passbolt login status",
	RunE: func(cmd *cobra.Command, args []string) error {
		profile, err := passbolt.NewConfigStore(viper.GetViper()).GetProfile(viper.GetString("profile"))
		if err != nil {
			return err
		}
		auth, err := authServiceFromCommand(cmd, passbolt.NewOSKeyringStore())
		if err != nil {
			return err
		}
		if _, err := auth.AuthenticatedClient(context.Background(), profile, passboltClientOptions()...); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Profile %q is authenticated\n", profile.Name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd, logoutCmd, statusCmd)
	loginCmd.Flags().String("totp", "", "TOTP code for MFA")
	addPassphraseEnvFlag(loginCmd)
	addPassphraseEnvFlag(statusCmd)
}
