package cmd

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

func readInjectInput(input string) (string, error) {
	if input != "" {
		// #nosec G304 -- CLI users intentionally choose the template path to read.
		data, err := os.ReadFile(input)
		if err != nil {
			return "", fmt.Errorf("read input %q: %w", input, err)
		}
		return string(data), nil
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return string(data), nil
}

func writeInjectOutput(stdout io.Writer, content, output, outputPermissions string) error {
	if output == "" {
		_, err := fmt.Fprint(stdout, content)
		return err
	}

	mode, err := parseFileMode(outputPermissions)
	if err != nil {
		return err
	}

	// #nosec G304 -- CLI users intentionally choose the output path to create or overwrite.
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open output %q: %w", output, err)
	}

	if _, err := fmt.Fprint(file, content); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("write output %q: %w; close: %v", output, err, closeErr)
		}
		return fmt.Errorf("write output %q: %w", output, err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close output %q: %w", output, err)
	}
	return nil
}

func parseFileMode(value string) (fs.FileMode, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("file mode cannot be empty")
	}
	if len(value) == 3 {
		value = "0" + value
	}
	if len(value) != 4 || value[0] != '0' {
		return 0, fmt.Errorf("file mode must be an octal mode like 0600, 0644, or 0755")
	}

	for _, r := range value {
		if r < '0' || r > '7' {
			return 0, fmt.Errorf("file mode must be octal digits only, got %q", value)
		}
	}

	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid file mode %q: %w", value, err)
	}

	mode := fs.FileMode(parsed)
	if mode&^0777 != 0 {
		return 0, fmt.Errorf("file mode must only contain permission bits, got %q", value)
	}
	return mode, nil
}
