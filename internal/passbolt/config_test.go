package passbolt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestConfigStoreProfilesDoNotPersistSecrets(t *testing.T) {
	t.Parallel()

	v := viper.New()
	v.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	v.SetConfigType("yaml")
	store := NewConfigStore(v)

	err := store.UpsertProfile(Profile{
		Name:      "default",
		ServerURL: "https://passbolt.test/",
		UserID:    "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
		Username:  "ada@example.test",
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	profile, err := store.GetProfile("")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "default" {
		t.Fatalf("unexpected default profile: %q", profile.Name)
	}
	if profile.ServerURL != "https://passbolt.test" {
		t.Fatalf("server URL was not normalized: %q", profile.ServerURL)
	}

	data, err := os.ReadFile(v.ConfigFileUsed())
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, secretWord := range []string{"private_key", "passphrase", "access_token", "refresh_token"} {
		if strings.Contains(content, secretWord) {
			t.Fatalf("config contains secret marker %q:\n%s", secretWord, content)
		}
	}
}

func TestAccountKitParserFindsNestedFields(t *testing.T) {
	t.Parallel()

	kit, err := ParseAccountKit([]byte(`{
		"domain": "https://passbolt.test/",
		"user": {"id": "8bb80df5-700c-48ce-b568-85a60fc3c8f2", "username": "ada@example.test"},
		"keys": {"private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nkey\n-----END PGP PRIVATE KEY BLOCK-----"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if kit.ServerURL != "https://passbolt.test" {
		t.Fatalf("unexpected server URL: %q", kit.ServerURL)
	}
	if kit.UserID != "8bb80df5-700c-48ce-b568-85a60fc3c8f2" {
		t.Fatalf("unexpected user id: %q", kit.UserID)
	}
	if kit.Username != "ada@example.test" {
		t.Fatalf("unexpected username: %q", kit.Username)
	}
	if !strings.Contains(kit.PrivateKey, "PGP PRIVATE KEY") {
		t.Fatalf("private key not parsed: %q", kit.PrivateKey)
	}
}

func TestAccountKitParserHandlesBase64ClearSignedJSON(t *testing.T) {
	t.Parallel()

	encoded := "LS0tLS1CRUdJTiBQR1AgU0lHTkVEIE1FU1NBR0UtLS0tLQpIYXNoOiBTSEE1MTIKCnsKICAiZG9tYWluIjogImh0dHBzOi8vcGFzc2JvbHQudGVzdCIsCiAgInVzZXJfaWQiOiAiOGJiODBkZjUtNzAwYy00OGNlLWI1NjgtODVhNjBmYzNjOGYyIiwKICAidXNlcm5hbWUiOiAiYWRhQGV4YW1wbGUudGVzdCIsCiAgInVzZXJfcHJpdmF0ZV9hcm1vcmVkX2tleSI6ICItLS0tLUJFR0lOIFBHUCBQUklWQVRFIEtFWSBCTE9DSy0tLS0tXG5rZXlcbi0tLS0tRU5EIFBHUCBQUklWQVRFIEtFWSBCTE9DSy0tLS0tIgp9Ci0tLS0tQkVHSU4gUEdQIFNJR05BVFVSRS0tLS0tCgpzaWduYXR1cmUKLS0tLS1FTkQgUEdQIFNJR05BVFVSRS0tLS0tCg=="
	kit, err := ParseAccountKit([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if kit.ServerURL != "https://passbolt.test" {
		t.Fatalf("unexpected server URL: %q", kit.ServerURL)
	}
	if kit.UserID != "8bb80df5-700c-48ce-b568-85a60fc3c8f2" {
		t.Fatalf("unexpected user id: %q", kit.UserID)
	}
	if kit.Username != "ada@example.test" {
		t.Fatalf("unexpected username: %q", kit.Username)
	}
	if !strings.Contains(kit.PrivateKey, "PGP PRIVATE KEY") {
		t.Fatalf("private key not parsed: %q", kit.PrivateKey)
	}
}
