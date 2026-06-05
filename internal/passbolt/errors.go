package passbolt

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrResourceNotFound      = errors.New("resource not found")
	ErrResourceNameAmbiguous = errors.New("resource name is ambiguous")
	ErrSecretNotDecryptable  = errors.New("secret not decryptable with profile private key")
)

func apiResponseError(operation, status string, body []byte) error {
	msg := fmt.Sprintf("%s: %s", operation, status)
	if excerpt := apiBodyExcerpt(body); excerpt != "" {
		msg += " " + excerpt
	}
	return errors.New(msg)
}

func apiBodyExcerpt(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}
	const maxLen = 256
	if len(trimmed) > maxLen {
		return fmt.Sprintf("(%s…)", trimmed[:maxLen])
	}
	return fmt.Sprintf("(%s)", trimmed)
}

func wrapPGPError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "incorrect key"):
		return fmt.Errorf("%w: PGP message was not encrypted for this private key", ErrSecretNotDecryptable)
	case strings.Contains(msg, "integrity protected"):
		return fmt.Errorf("PGP message failed integrity check: %w", err)
	case strings.Contains(msg, "malformed"):
		return fmt.Errorf("PGP message is malformed: %w", err)
	default:
		return fmt.Errorf("PGP decrypt: %w", err)
	}
}
