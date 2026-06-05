package passbolt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gopenpgp "github.com/ProtonMail/gopenpgp/v3/crypto"
)

func TestAuthServiceLoginStoresJWTSecrets(t *testing.T) {
	t.Parallel()

	userKey := testKey(t, "Ada", "ada@example.test")
	serverKey := testKey(t, "Passbolt", "server@example.test")
	userPublic, err := userKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := serverKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var sawTOTP bool

	store := newMemorySecretStore()
	if err := store.Set("default", SecretPrivateKey, mustArmor(t, userKey)); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("default", SecretPrivateKeyPass, ""); err != nil {
		t.Fatal(err)
	}

	pgp := NewPGPService()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/verify.json":
			writeJSON(t, w, map[string]any{
				"header": testHeader(200, "/auth/verify.json"),
				"body": map[string]any{
					"fingerprint": serverKey.GetFingerprint(),
					"keydata":     serverPublic,
				},
			})
		case "/auth/jwt/login.json":
			tokens, err := pgp.EncryptAndSignJSON(TokenSet{
				AccessToken:  "jwt.access.token",
				RefreshToken: "ad71952e-7842-599e-a19e-3a82e6974b23",
			}, mustPublicKey(t, userPublic), serverKey)
			if err != nil {
				t.Fatal(err)
			}
			writeJSON(t, w, map[string]any{
				"header": testHeader(200, "/auth/jwt/login.json"),
				"body":   map[string]any{"challenge": tokens},
			})
		case "/mfa/verify/totp.json":
			if got := r.Header.Get("Authorization"); got != "Bearer jwt.access.token" {
				t.Fatalf("unexpected MFA authorization header: %q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["totp"] != "123456" {
				t.Fatalf("unexpected totp body: %#v", body)
			}
			sawTOTP = true
			writeJSON(t, w, map[string]any{
				"header": testHeader(200, "/mfa/verify/totp.json"),
				"body":   nil,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	auth := NewAuthService(store)
	auth.Now = func() time.Time { return time.Unix(1000, 0) }
	_, err = auth.Login(context.Background(), Profile{
		Name:      "default",
		ServerURL: server.URL,
		UserID:    "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
	}, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if !sawTOTP {
		t.Fatal("expected TOTP verification request")
	}
	access, err := store.Get("default", SecretAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if access != "jwt.access.token" {
		t.Fatalf("unexpected access token: %q", access)
	}
	refresh, err := store.Get("default", SecretRefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refresh != "ad71952e-7842-599e-a19e-3a82e6974b23" {
		t.Fatalf("unexpected refresh token: %q", refresh)
	}
}

func TestAuthServiceLoginDoesNotPersistJWTSecretsWhenMFAFails(t *testing.T) {
	t.Parallel()

	userKey := testKey(t, "Ada", "ada@example.test")
	serverKey := testKey(t, "Passbolt", "server@example.test")
	userPublic, err := userKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := serverKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	store := newMemorySecretStore()
	if err := store.Set("default", SecretPrivateKey, mustArmor(t, userKey)); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("default", SecretPrivateKeyPass, ""); err != nil {
		t.Fatal(err)
	}

	pgp := NewPGPService()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/verify.json":
			writeJSON(t, w, map[string]any{
				"header": testHeader(200, "/auth/verify.json"),
				"body": map[string]any{
					"fingerprint": serverKey.GetFingerprint(),
					"keydata":     serverPublic,
				},
			})
		case "/auth/jwt/login.json":
			tokens, err := pgp.EncryptAndSignJSON(TokenSet{
				AccessToken:  "jwt.access.token",
				RefreshToken: "ad71952e-7842-599e-a19e-3a82e6974b23",
			}, mustPublicKey(t, userPublic), serverKey)
			if err != nil {
				t.Fatal(err)
			}
			writeJSON(t, w, map[string]any{
				"header": testHeader(200, "/auth/jwt/login.json"),
				"body":   map[string]any{"challenge": tokens},
			})
		case "/mfa/verify/totp.json":
			if got := r.Header.Get("Authorization"); got != "Bearer jwt.access.token" {
				t.Fatalf("unexpected MFA authorization header: %q", got)
			}
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(t, w, map[string]any{
				"header": testHeader(400, "/mfa/verify/totp.json"),
				"body":   "",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	_, err = NewAuthService(store).Login(context.Background(), Profile{
		Name:      "default",
		ServerURL: server.URL,
		UserID:    "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
	}, "000000")
	if err == nil {
		t.Fatal("expected login to fail")
	}
	if _, err := store.Get("default", SecretAccessToken); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("access token should not be stored after MFA failure, got %v", err)
	}
	if _, err := store.Get("default", SecretRefreshToken); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("refresh token should not be stored after MFA failure, got %v", err)
	}
}

func TestAuthServiceRefreshStoresNewAccessToken(t *testing.T) {
	t.Parallel()

	store := newMemorySecretStore()
	if err := store.Set("default", SecretRefreshToken, "ad71952e-7842-599e-a19e-3a82e6974b23"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/auth/jwt/refresh.json" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  "refresh_token",
			Value: "f8cea352-6bd3-4944-9523-20b31272bef0",
		})
		writeJSON(t, w, map[string]any{
			"header": testHeader(200, "/auth/jwt/refresh.json"),
			"body":   map[string]any{"access_token": "jwt.refreshed.token"},
		})
	}))
	t.Cleanup(server.Close)

	access, err := NewAuthService(store).Refresh(context.Background(), Profile{
		Name:      "default",
		ServerURL: server.URL,
		UserID:    "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if access != "jwt.refreshed.token" {
		t.Fatalf("unexpected access token: %q", access)
	}
	stored, err := store.Get("default", SecretAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if stored != access {
		t.Fatalf("stored access token mismatch: %q", stored)
	}
	refresh, err := store.Get("default", SecretRefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refresh != "f8cea352-6bd3-4944-9523-20b31272bef0" {
		t.Fatalf("stored refresh token mismatch: %q", refresh)
	}
}

func testKey(t *testing.T, name, email string) *gopenpgp.Key {
	t.Helper()
	key, err := gopenpgp.PGP().KeyGeneration().AddUserId(name, email).New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustArmor(t *testing.T, key *gopenpgp.Key) string {
	t.Helper()
	armored, err := key.Armor()
	if err != nil {
		t.Fatal(err)
	}
	return armored
}

func mustPublicKey(t *testing.T, armored string) *gopenpgp.Key {
	t.Helper()
	key, err := gopenpgp.NewKeyFromArmored(armored)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func testHeader(code int, path string) map[string]any {
	return map[string]any{
		"id":         "7ff2828c-1092-4897-8e0a-1dc64ada889f",
		"status":     "success",
		"servertime": 1721207029,
		"action":     "4d0c0996-ce30-4bce-9918-9062ab35c542",
		"message":    "ok",
		"url":        path,
		"code":       code,
	}
}
