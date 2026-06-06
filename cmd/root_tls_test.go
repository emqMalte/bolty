package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func TestInsecureSkipTLSFlagDefaultsToFalse(t *testing.T) {
	insecureSkipTLSVerify = true
	t.Cleanup(func() { insecureSkipTLSVerify = false })

	cmd := testTLSFlagCommand()
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if insecureSkipTLSVerify {
		t.Fatal("insecureSkipTLSVerify should default to false when flag is omitted")
	}
}

func TestInsecureSkipTLSFlagMustBeExplicit(t *testing.T) {
	insecureSkipTLSVerify = false
	t.Cleanup(func() { insecureSkipTLSVerify = false })

	cmd := testTLSFlagCommand()
	cmd.SetArgs([]string{"--insecure-skip-tls-verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !insecureSkipTLSVerify {
		t.Fatal("insecureSkipTLSVerify should be true only when the flag is explicitly set")
	}
}

func testTLSFlagCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {},
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS certificate verification")
	return cmd
}
