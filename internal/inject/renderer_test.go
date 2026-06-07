package inject

import (
	"context"
	"encoding/base32"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emqmalte/bolty/internal/passbolt"
)

func TestRenderReplacesPassboltPlaceholders(t *testing.T) {
	t.Parallel()

	resource := passbolt.DecryptedResource{
		ID: "database-id",
		Metadata: map[string]any{
			"username": "ada",
			"custom_fields": []any{
				map[string]any{"name": "env", "value": "prod"},
			},
		},
		Secrets: []any{
			map[string]any{"password": "s3cr3t"},
		},
	}

	calls := 0
	rendered, err := Render(context.Background(), strings.Join([]string{
		`DATABASE_URL=postgres://{{passbolt://database/username}}:{{passbolt://database/password}}@localhost/app`,
		`APP_ENV={{passbolt://database/custom/env}}`,
	}, "\n"), func(_ context.Context, ref string) (passbolt.DecryptedResource, error) {
		calls++
		if ref != "database" {
			t.Fatalf("unexpected resource ref: %q", ref)
		}
		return resource, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		`DATABASE_URL=postgres://ada:s3cr3t@localhost/app`,
		`APP_ENV=prod`,
	}, "\n")
	if rendered != want {
		t.Fatalf("unexpected rendered template:\n%s", rendered)
	}
	if calls != 1 {
		t.Fatalf("resource should be loaded once and reused, got %d calls", calls)
	}
}

func TestRenderReturnsResourceNotFound(t *testing.T) {
	t.Parallel()

	_, err := Render(context.Background(), `TOKEN={{passbolt://missing/password}}`, func(_ context.Context, ref string) (passbolt.DecryptedResource, error) {
		return passbolt.DecryptedResource{}, passbolt.ErrResourceNotFound
	})
	if !errors.Is(err, passbolt.ErrResourceNotFound) {
		t.Fatalf("expected resource not found error, got %v", err)
	}
	if !strings.Contains(err.Error(), `missing resource "missing"`) {
		t.Fatalf("error should name the missing resource, got %v", err)
	}
}

func TestRenderInjectsCurrentCodeFromPassboltTOTPObject(t *testing.T) {
	t.Parallel()

	rendered, err := Render(context.Background(), `TOTP={{passbolt://api/totp}}`, func(_ context.Context, _ string) (passbolt.DecryptedResource, error) {
		return passbolt.DecryptedResource{
			ID:            "api-id",
			DecryptedName: "API",
			Secrets: []any{map[string]any{"totp": map[string]any{
				"secret_key": "DAV3DS4ERAAF5QGH",
				"period":     float64(30),
				"digits":     float64(6),
				"algorithm":  "SHA1",
			}}},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^TOTP=\d{6}$`).MatchString(rendered) {
		t.Fatalf("unexpected rendered TOTP: %q", rendered)
	}
}

func TestRenderRequiresResolverWhenTemplateHasPlaceholders(t *testing.T) {
	t.Parallel()

	_, err := Render(context.Background(), `TOKEN={{passbolt://api/password}}`, nil)
	if err == nil || !strings.Contains(err.Error(), "resource resolver is required") {
		t.Fatalf("expected resolver error, got %v", err)
	}
}

func TestRenderStopsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Render(ctx, `TOKEN={{passbolt://api/password}}`, func(_ context.Context, ref string) (passbolt.DecryptedResource, error) {
		t.Fatal("resolver should not be called after cancellation")
		return passbolt.DecryptedResource{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}

func TestPassboltRefValueSupportsSecretStringPassword(t *testing.T) {
	t.Parallel()

	value, err := passboltRefValue(passbolt.DecryptedResource{
		ID:      "api-id",
		Secrets: []any{"plain-secret"},
	}, PassboltRef{
		Resource: "api",
		Field:    FieldPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != "plain-secret" {
		t.Fatalf("unexpected value: %q", value)
	}
}

func TestPassboltRefValueFindsURIString(t *testing.T) {
	t.Parallel()

	value, err := passboltRefValue(passbolt.DecryptedResource{
		ID:       "api-id",
		Metadata: map[string]any{"uri": "https://passbolt.test"},
	}, PassboltRef{
		Resource: "api",
		Field:    FieldURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != "https://passbolt.test" {
		t.Fatalf("unexpected value: %q", value)
	}
}

func TestPassboltRefValueFindsStableFields(t *testing.T) {
	t.Parallel()

	resource := passbolt.DecryptedResource{
		ID:            "api-id",
		DecryptedName: "api",
		Metadata: map[string]any{
			"username":    "ada",
			"uri":         "https://api.test",
			"description": "API password",
		},
		Secrets: []any{
			map[string]any{
				"password": "secret",
				"totp":     "123456",
			},
		},
	}
	cases := map[FieldKind]string{
		FieldName:     "api",
		FieldUsername: "ada",
		FieldPassword: "secret",
		FieldURI:      "https://api.test",
		FieldURL:      "https://api.test",
		FieldDesc:     "API password",
		FieldTOTP:     "123456",
	}
	for field, want := range cases {
		got, err := passboltRefValue(resource, PassboltRef{Resource: "api", Field: field})
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if got != want {
			t.Fatalf("%s = %q, want %q", field, got, want)
		}
	}
}

func TestPassboltRefValueFindsFirstNonEmptyURI(t *testing.T) {
	t.Parallel()

	value, err := passboltRefValue(passbolt.DecryptedResource{
		ID: "api-id",
		Metadata: map[string]any{
			"uris": []any{"", "https://primary.test", "https://secondary.test"},
		},
	}, PassboltRef{
		Resource: "api",
		Field:    FieldURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != "https://primary.test" {
		t.Fatalf("unexpected value: %q", value)
	}
}

func TestGenerateTOTPRFC6238Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algorithm string
		secret    string
		want      string
	}{
		{"SHA1", "12345678901234567890", "94287082"},
		{"SHA256", "12345678901234567890123456789012", "46119246"},
		{"SHA512", "1234567890123456789012345678901234567890123456789012345678901234", "90693936"},
	}
	for _, test := range tests {
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(test.secret))
		got, err := generateTOTP(secret, test.algorithm, 8, 30, time.Unix(59, 0))
		if err != nil {
			t.Fatalf("%s: %v", test.algorithm, err)
		}
		if got != test.want {
			t.Fatalf("%s = %q, want %q", test.algorithm, got, test.want)
		}
	}
}

func TestTOTPFieldCalculatesCodeFromProvisioningURI(t *testing.T) {
	t.Parallel()

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	status, ok := totpField(map[string]any{
		"totp": "otpauth://totp/API?secret=" + secret + "&algorithm=SHA1&digits=8&period=30",
	}, time.Unix(59, 0), true)
	if !ok || status.Code != "94287082" {
		t.Fatalf("totpField() = %#v, %v", status, ok)
	}
	if status.Period != 30*time.Second || !status.ExpiresAt.Equal(time.Unix(60, 0)) {
		t.Fatalf("unexpected TOTP timing: %#v", status)
	}
}

func TestTOTPInfoDoesNotGenerateCode(t *testing.T) {
	t.Parallel()

	resource := passbolt.DecryptedResource{
		Secrets: []any{map[string]any{"totp": map[string]any{
			"secret_key": "DAV3DS4ERAAF5QGH",
			"period":     float64(45),
			"digits":     float64(6),
			"algorithm":  "SHA1",
		}}},
	}
	status, ok := TOTPInfoAt(resource, time.Unix(70, 0))
	if !ok {
		t.Fatal("expected TOTP metadata")
	}
	if status.Code != "" {
		t.Fatalf("TOTP metadata generated a code: %q", status.Code)
	}
	if status.Digits != 6 || status.Period != 45*time.Second || !status.ExpiresAt.Equal(time.Unix(90, 0)) {
		t.Fatalf("unexpected TOTP metadata: %#v", status)
	}
}

func TestPassboltRefValueReportsMissingURI(t *testing.T) {
	t.Parallel()

	_, err := passboltRefValue(passbolt.DecryptedResource{
		ID:       "api-id",
		Metadata: map[string]any{"uris": []any{"", " "}},
	}, PassboltRef{
		Resource: "api",
		Field:    FieldURI,
	})
	if err == nil {
		t.Fatal("expected missing uri error")
	}
	if !strings.Contains(err.Error(), "does not contain a uri") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPassboltRefValueFindsV5CustomFieldSecretValue(t *testing.T) {
	t.Parallel()

	value, err := passboltRefValue(passbolt.DecryptedResource{
		ID: "api-id",
		Metadata: map[string]any{
			"custom_fields": []any{
				map[string]any{
					"id":           "fc71fb76-82f0-40e3-992a-738255b5d0c2",
					"metadata_key": "Huhu",
					"type":         "text",
				},
			},
		},
		Secrets: []any{
			map[string]any{
				"custom_fields": []any{
					map[string]any{
						"id":           "fc71fb76-82f0-40e3-992a-738255b5d0c2",
						"secret_value": "Field",
						"type":         "text",
					},
				},
				"password": "Testpassword",
			},
		},
	}, PassboltRef{
		Resource:    "api",
		Field:       FieldCustom,
		CustomField: "Huhu",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != "Field" {
		t.Fatalf("unexpected value: %q", value)
	}
}

func TestPassboltRefValueReportsMissingCustomField(t *testing.T) {
	t.Parallel()

	_, err := passboltRefValue(passbolt.DecryptedResource{
		ID:       "api-id",
		Metadata: map[string]any{"custom_fields": []any{map[string]any{"name": "env", "value": "prod"}}},
	}, PassboltRef{
		Resource:    "api",
		Field:       FieldCustom,
		CustomField: "region",
	})
	if err == nil {
		t.Fatal("expected missing custom field error")
	}
	if !strings.Contains(err.Error(), `custom field "region"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
