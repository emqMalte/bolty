package inject

import (
	"strings"
	"testing"
)

func TestParsePassboltRef(t *testing.T) {
	t.Parallel()

	ref, err := ParsePassboltRef("passbolt://Test%20Password%201/custom/Huhu")
	if err != nil {
		t.Fatal(err)
	}
	if ref.ResourceKind != RefName {
		t.Fatalf("unexpected resource kind: %q", ref.ResourceKind)
	}
	if ref.Resource != "Test Password 1" {
		t.Fatalf("unexpected resource: %q", ref.Resource)
	}
	if ref.Field != FieldCustom {
		t.Fatalf("unexpected field kind: %q", ref.Field)
	}
	if ref.CustomField != "Huhu" {
		t.Fatalf("unexpected custom field: %q", ref.CustomField)
	}
}

func TestParsePassboltRefSupportsEscapedSlashesInsideSegments(t *testing.T) {
	t.Parallel()

	ref, err := ParsePassboltRef("passbolt://Folder%2FAPI/custom/header%2Ftoken")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Resource != "Folder/API" {
		t.Fatalf("unexpected resource: %q", ref.Resource)
	}
	if ref.CustomField != "header/token" {
		t.Fatalf("unexpected custom field: %q", ref.CustomField)
	}
}

func TestParsePassboltRefAcceptsCaseInsensitiveScheme(t *testing.T) {
	t.Parallel()

	ref, err := ParsePassboltRef("PASSBOLT://api/password")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Resource != "api" || ref.Field != FieldPassword {
		t.Fatalf("unexpected ref: %#v", ref)
	}
}

func TestParsePassboltRefSupportsURIField(t *testing.T) {
	t.Parallel()

	ref, err := ParsePassboltRef("passbolt://api/uri")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Resource != "api" || ref.Field != FieldURI {
		t.Fatalf("unexpected ref: %#v", ref)
	}
}

func TestParsePassboltRefSupportsStableFields(t *testing.T) {
	t.Parallel()

	cases := map[string]FieldKind{
		"name":        FieldName,
		"username":    FieldUsername,
		"password":    FieldPassword,
		"uri":         FieldURI,
		"url":         FieldURL,
		"description": FieldDesc,
		"totp":        FieldTOTP,
	}
	for field, want := range cases {
		ref, err := ParsePassboltRef("passbolt://api/" + field)
		if err != nil {
			t.Fatalf("parse %s: %v", field, err)
		}
		if ref.Field != want {
			t.Fatalf("field %s parsed as %q, want %q", field, ref.Field, want)
		}
	}
}

func TestParsePassboltRefRejectsAmbiguousPathSegments(t *testing.T) {
	t.Parallel()

	_, err := ParsePassboltRef("passbolt://api/custom/")
	if err == nil || !strings.Contains(err.Error(), "empty segment") {
		t.Fatalf("expected empty segment error, got %v", err)
	}
}

func TestParsePassboltRefRejectsQueryAndFragment(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"passbolt://api/password?debug=true",
		"passbolt://api/password#token",
	} {
		_, err := ParsePassboltRef(input)
		if err == nil || !strings.Contains(err.Error(), "query or fragment") {
			t.Fatalf("expected query/fragment error for %q, got %v", input, err)
		}
	}
}
