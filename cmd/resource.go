/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"encoding/json"
	"io"

	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var resourcesCmd = &cobra.Command{
	Use:   "resources",
	Short: "Read Passbolt resources",
}

var resourcesGetCmd = &cobra.Command{
	Use:   "get <id-or-name>",
	Short: "Retrieve and decrypt a Passbolt resource",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			service.Debug = cmd.ErrOrStderr()
		}
		resource, err := service.Get(context.Background(), profile, args[0], passboltClientOptions()...)
		if err != nil {
			return err
		}
		return writeResourceOutput(cmd.OutOrStdout(), resource, debug)
	},
}

var resourcesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Passbolt resources",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store := passbolt.NewConfigStore(viper.GetViper())
		profile, err := store.GetProfile(viper.GetString("profile"))
		if err != nil {
			return err
		}
		search, _ := cmd.Flags().GetString("search")
		storeSecrets := passbolt.NewOSKeyringStore()
		service := passbolt.NewResourceService(storeSecrets)
		auth, err := authServiceFromCommand(cmd, storeSecrets)
		if err != nil {
			return err
		}
		service.Auth = auth
		resources, err := service.List(context.Background(), profile, search, passboltClientOptions()...)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(resources)
	},
}

func writeResourceOutput(w io.Writer, resource passbolt.DecryptedResource, debug bool) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if debug {
		return encoder.Encode(struct {
			passbolt.DecryptedResource
			RawResource any `json:"raw_resource,omitempty"`
		}{
			DecryptedResource: resource,
			RawResource:       resource.RawResource,
		})
	}
	return encoder.Encode(resource)
}

func init() {
	rootCmd.AddCommand(resourcesCmd)
	resourcesCmd.AddCommand(resourcesGetCmd, resourcesListCmd)
	resourcesGetCmd.Flags().Bool("debug", false, "Print resource lookup diagnostics without decrypted secret values")
	resourcesListCmd.Flags().String("search", "", "Filter resources by visible summary fields")
	addPassphraseEnvFlag(resourcesGetCmd)
	addPassphraseEnvFlag(resourcesListCmd)
}
