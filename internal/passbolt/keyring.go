package passbolt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

const KeyringService = "bolty"

var ErrSecretNotFound = errors.New("secret not found")

// SecretStore stores sensitive profile material outside the config file.
type SecretStore interface {
	Set(profile, name, value string) error
	Get(profile, name string) (string, error)
	Delete(profile, name string) error
	DeleteProfile(profile string) error
}

type OSKeyringStore struct {
	Service string
}

func NewOSKeyringStore() OSKeyringStore {
	return OSKeyringStore{Service: KeyringService}
}

func (s OSKeyringStore) Set(profile, name, value string) error {
	return keyring.Set(s.service(), secretUser(profile, name), value)
}

func (s OSKeyringStore) Get(profile, name string) (string, error) {
	value, err := keyring.Get(s.service(), secretUser(profile, name))
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrSecretNotFound
		}
		return "", err
	}
	return value, nil
}

func (s OSKeyringStore) Delete(profile, name string) error {
	err := keyring.Delete(s.service(), secretUser(profile, name))
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrSecretNotFound
	}
	return err
}

func (s OSKeyringStore) DeleteProfile(profile string) error {
	for _, name := range ProfileSecretNames() {
		if err := s.Delete(profile, name); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
	}
	return nil
}

func (s OSKeyringStore) service() string {
	if strings.TrimSpace(s.Service) == "" {
		return KeyringService
	}
	return s.Service
}

const (
	SecretPrivateKey         = "private_key"
	SecretPrivateKeyPass     = "private_key_passphrase"
	SecretAccessToken        = "access_token"
	SecretRefreshToken       = "refresh_token"
	SecretMetadataSessionKey = "metadata_session_key"
)

func ProfileSecretNames() []string {
	return []string{
		SecretPrivateKey,
		SecretPrivateKeyPass,
		SecretAccessToken,
		SecretRefreshToken,
		SecretMetadataSessionKey,
	}
}

func secretUser(profile, name string) string {
	return fmt.Sprintf("profile:%s:%s", strings.TrimSpace(profile), strings.TrimSpace(name))
}
