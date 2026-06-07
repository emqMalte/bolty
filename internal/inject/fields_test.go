package inject

import (
	"strings"
	"testing"

	"github.com/emqmalte/bolty/internal/passbolt"
)

func TestAvailableFieldsReturnsResolvableFieldsInStableOrder(t *testing.T) {
	t.Parallel()

	resource := passbolt.DecryptedResource{
		ID:            "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
		DecryptedName: "api",
		Metadata: map[string]any{
			"username": "ada",
			"uri":      "https://api.test",
			"custom_fields": []any{
				map[string]any{"name": "region", "value": "eu"},
				map[string]any{"name": "empty", "value": ""},
				map[string]any{"name": "env", "value": "prod"},
			},
		},
		Secrets: []any{map[string]any{
			"password": "secret",
			"totp": map[string]any{
				"secret_key": "DAV3DS4ERAAF5QGH",
				"period":     float64(30),
				"digits":     float64(6),
				"algorithm":  "SHA1",
			},
		}},
	}

	fields := AvailableFields(resource)
	got := make([]string, len(fields))
	for i, field := range fields {
		got[i] = field.Selector
	}
	want := []string{"name", "username", "password", "uri", "totp", "custom/env", "custom/region"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("AvailableFields() = %v, want %v", got, want)
	}
}

func TestAvailableFieldsFindsV5SecretBackedCustomField(t *testing.T) {
	t.Parallel()

	resource := passbolt.DecryptedResource{
		ID: "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
		Metadata: map[string]any{"custom_fields": []any{map[string]any{
			"id":           "fc71fb76-82f0-40e3-992a-738255b5d0c2",
			"metadata_key": "header/token",
		}}},
		Secrets: []any{map[string]any{"custom_fields": []any{map[string]any{
			"id":           "fc71fb76-82f0-40e3-992a-738255b5d0c2",
			"secret_value": "secret",
		}}}},
	}

	fields := AvailableFields(resource)
	if len(fields) != 1 || fields[0].Selector != "custom/header/token" {
		t.Fatalf("unexpected fields: %#v", fields)
	}
}

func TestAvailableFieldsFindsPassboltTOTPObject(t *testing.T) {
	t.Parallel()

	resource := passbolt.DecryptedResource{
		ID:            "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
		DecryptedName: "API",
		Secrets: []any{map[string]any{"totp": map[string]any{
			"secret_key": "DAV3DS4ERAAF5QGH",
			"period":     float64(30),
			"digits":     float64(6),
			"algorithm":  "SHA1",
		}}},
	}

	fields := AvailableFields(resource)
	if len(fields) != 2 || fields[0].Selector != "name" || fields[1].Selector != "totp" {
		t.Fatalf("unexpected fields: %#v", fields)
	}
}

func TestBuildPlaceholderUsesUUIDAndEscapesCustomField(t *testing.T) {
	t.Parallel()

	placeholder, err := BuildPlaceholder(
		"ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
		"custom/header/token",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "{{ passbolt://ae60d89c-f13b-4fb1-b2dc-c8dc806cac88/custom/header%2Ftoken }}"
	if placeholder != want {
		t.Fatalf("BuildPlaceholder() = %q, want %q", placeholder, want)
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(placeholder, "{{"), "}}"))
	ref, err := ParsePassboltRef(inner)
	if err != nil {
		t.Fatal(err)
	}
	if ref.CustomField != "header/token" {
		t.Fatalf("unexpected custom field: %q", ref.CustomField)
	}
}

func TestBuildPlaceholderRejectsResourceName(t *testing.T) {
	t.Parallel()

	if _, err := BuildPlaceholder("api", "password"); err == nil {
		t.Fatal("expected non-UUID resource to be rejected")
	}
}
