package cmd

import (
	"bytes"
	"os"
	"testing"
)

func TestReadInjectInputPreservesStdinNewline(t *testing.T) {
	originalStdin := os.Stdin
	t.Cleanup(func() {
		os.Stdin = originalStdin
	})

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("hello\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = reader

	got, err := readInjectInput("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello\n" {
		t.Fatalf("stdin should be preserved exactly, got %q", got)
	}
}

func TestWriteInjectOutputUsesProvidedStdout(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := writeInjectOutput(&stdout, "rendered", "", "0600"); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "rendered" {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestParseFileMode(t *testing.T) {
	t.Parallel()

	mode, err := parseFileMode("0600")
	if err != nil {
		t.Fatal(err)
	}
	if mode != 0600 {
		t.Fatalf("unexpected mode: %v", mode)
	}

	mode, err = parseFileMode("640")
	if err != nil {
		t.Fatal(err)
	}
	if mode != 0640 {
		t.Fatalf("unexpected shorthand mode: %v", mode)
	}

	if _, err := parseFileMode("999"); err == nil {
		t.Fatal("expected invalid octal mode error")
	}
	if _, err := parseFileMode("10600"); err == nil {
		t.Fatal("expected invalid file mode width error")
	}
}
