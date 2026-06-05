package cmd

import (
	"fmt"

	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage Passbolt profiles",
}

var profileAddCmd = &cobra.Command{
	Use:   "add [name]",
	Short: "Add a Passbolt profile",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profileName := passbolt.DefaultProfileName
		if len(args) == 1 {
			profileName = args[0]
		}
		opts, err := configureOptionsFromCommand(cmd, profileName)
		if err != nil {
			return err
		}
		if err := runConfigure(cmd, opts); err != nil {
			return err
		}
		if profileName == passbolt.DefaultProfileName {
			fmt.Fprintln(cmd.OutOrStdout(), "Use it with: bolty login")
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Use it with: bolty --profile %s login\n", profileName)
		}
		return nil
	},
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Passbolt profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		names, defaultProfile, err := passbolt.NewConfigStore(viper.GetViper()).ProfileNames()
		if err != nil {
			return err
		}
		for _, name := range names {
			marker := " "
			if name == defaultProfile {
				marker = "*"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", marker, name)
		}
		return nil
	},
}

var profileSetDefaultCmd = &cobra.Command{
	Use:   "set-default <name>",
	Short: "Set the default Passbolt profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := passbolt.NewConfigStore(viper.GetViper()).SetDefaultProfile(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Default profile set to %q\n", args[0])
		return nil
	},
}

var profileRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a Passbolt profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := passbolt.NewConfigStore(viper.GetViper()).RemoveProfile(args[0]); err != nil {
			return err
		}
		if err := passbolt.NewOSKeyringStore().DeleteProfile(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Profile %q removed\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(profileCmd)
	profileCmd.AddCommand(profileAddCmd, profileListCmd, profileSetDefaultCmd, profileRemoveCmd)
	addConfigureFlags(profileAddCmd)
}
