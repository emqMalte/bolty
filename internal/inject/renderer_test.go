package inject

import (
	"context"
	"errors"
	"strings"
	"testing"

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
				"totp":     "otpauth://totp/api",
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
		FieldTOTP:     "otpauth://totp/api",
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
