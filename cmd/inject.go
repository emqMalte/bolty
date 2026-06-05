/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"

	injectcore "github.com/emqmalte/bolty/internal/inject"
	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var injectCmd = &cobra.Command{
	Use:          "inject",
	Short:        "Inject Passbolt values into a template",
	SilenceUsage: true,
	Args:         cobra.NoArgs,
	Long: `Inject Passbolt values into a template.

Placeholders must use the form {{ passbolt://<resource-id-or-name>/<field> }}.
Supported fields are name, username, password, uri, url, description, totp, and custom/<field-name>.`,
	RunE: runInject,
}

func init() {
	rootCmd.AddCommand(injectCmd)

	injectCmd.Flags().StringP("input", "i", "", "The filename of a template file to inject")
	injectCmd.Flags().StringP("output", "o", "", "Write the resulting data to a file instead of stdout")
	injectCmd.Flags().String("file-mode", "0600", "Permissions for newly created output file")
	addPassphraseEnvFlag(injectCmd)
}

func runInject(cmd *cobra.Command, args []string) error {
	input, err := cmd.Flags().GetString("input")
	if err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	fileMode, err := cmd.Flags().GetString("file-mode")
	if err != nil {
		return err
	}

	template, err := readInjectInput(input)
	if err != nil {
		return err
	}

	store := passbolt.NewConfigStore(viper.GetViper())
	profile, err := store.GetProfile(viper.GetString("profile"))
	if err != nil {
		return err
	}

	storeSecrets := passbolt.NewOSKeyringStore()
	service := passbolt.NewResourceService(storeSecrets)
	auth, err := authServiceFromCommand(cmd, storeSecrets)
	if err != nil {
		return err
	}
	service.Auth = auth
	opts := passboltClientOptions()

	rendered, err := injectcore.Render(cmd.Context(), template, func(ctx context.Context, resourceRef string) (passbolt.DecryptedResource, error) {
		return service.Get(ctx, profile, resourceRef, opts...)
	})
	if err != nil {
		return err
	}

	return writeInjectOutput(cmd.OutOrStdout(), rendered, output, fileMode)
}
