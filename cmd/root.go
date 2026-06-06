/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const cliName = "bolty"

var cfgFile string
var insecureSkipTLSVerify bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     cliName,
	Short:   "A basic but powerful CLI to inject Passbolt secrets into local configuration files",
	Version: versionString(),
	Long: `Bolty is a CLI to inject Passbolt secrets into local configuration files.
	It is a basic but powerful tool to help you manage your secrets.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := initializeConfig(cmd); err != nil {
			return err
		}
		if insecureSkipTLSVerify && !isCompletionCommand(cmd) {
			fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: TLS certificate verification is disabled for this invocation.")
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/"+cliName+"/config.yaml)")
	rootCmd.PersistentFlags().String("profile", "", "Passbolt profile to use")
	rootCmd.PersistentFlags().String("server", "", "Passbolt server base URL")
	rootCmd.PersistentFlags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS certificate verification")
}

func initializeConfig(cmd *cobra.Command) error {
	viper.SetEnvPrefix("BOLTY")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if err := readConfig(viper.GetViper(), cfgFile, home); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	if err := viper.BindPFlags(cmd.InheritedFlags()); err != nil {
		return err
	}
	if err := viper.BindPFlags(cmd.PersistentFlags()); err != nil {
		return err
	}

	return nil
}

func readConfig(v *viper.Viper, explicitPath, home string) error {
	if explicitPath != "" {
		v.SetConfigFile(explicitPath)
	} else {
		// Do not search the working directory. Files such as ~/.ssh/config
		// are unrelated to Bolty and must never be parsed as YAML.
		v.AddConfigPath(filepath.Join(home, ".config", cliName))
		v.SetConfigName("config")
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return err
		}
	}
	return nil
}

func isCompletionCommand(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Name() == "completion" {
			return true
		}
	}
	return false
}
