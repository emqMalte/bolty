package passbolt

import (
	"testing"
)

func TestDecryptArmoredCanDecryptMultipleMessagesWithSameKey(t *testing.T) {
	t.Parallel()

	key := testKey(t, "Ada", "ada@example.test")
	public, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	pgp := NewPGPService()
	first, err := pgp.EncryptAndSign([]byte(`{"name":"first"}`), public, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pgp.EncryptAndSign([]byte(`{"password":"second"}`), public, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgp.DecryptArmored(first, key); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	if _, err := pgp.DecryptArmored(second, key); err != nil {
		t.Fatalf("second decrypt after first: %v", err)
	}
}
