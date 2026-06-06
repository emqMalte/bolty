package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestReadConfigIgnoresWorkingDirectoryConfig(t *testing.T) {
	workingDir := t.TempDir()
	home := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(workingDir, "config"),
		[]byte("Host *\n  AddKeysToAgent yes\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workingDir)

	v := viper.New()
	if err := readConfig(v, "", home); err != nil {
		t.Fatalf("readConfig parsed an unrelated working-directory config: %v", err)
	}
	if used := v.ConfigFileUsed(); used != "" {
		t.Fatalf("readConfig used %q; expected no config", used)
	}
}

func TestReadConfigUsesBoltyConfigDirectory(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", cliName)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "config.yml")
	if err := os.WriteFile(configPath, []byte("default_profile: default\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	if err := readConfig(v, "", home); err != nil {
		t.Fatal(err)
	}
	if used := v.ConfigFileUsed(); used != configPath {
		t.Fatalf("readConfig used %q; expected %q", used, configPath)
	}
}

func TestReadConfigUsesExplicitPath(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "custom.yaml")
	if err := os.WriteFile(configPath, []byte("default_profile: ci\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	if err := readConfig(v, configPath, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if used := v.ConfigFileUsed(); used != configPath {
		t.Fatalf("readConfig used %q; expected %q", used, configPath)
	}
}
