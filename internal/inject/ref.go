package inject

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const passboltSchemePrefix = "passbolt://"

type RefKind string

const (
	RefUUID RefKind = "uuid"
	RefName RefKind = "name"
)

type FieldKind string

const (
	FieldName     FieldKind = "name"
	FieldPassword FieldKind = "password"
	FieldUsername FieldKind = "username"
	FieldURI      FieldKind = "uri"
	FieldURL      FieldKind = "url"
	FieldDesc     FieldKind = "description"
	FieldTOTP     FieldKind = "totp"
	FieldCustom   FieldKind = "custom"
)

type PassboltRef struct {
	ResourceKind RefKind
	Resource     string
	Field        FieldKind
	CustomField  string
}

func ParsePassboltRef(s string) (PassboltRef, error) {
	original := strings.TrimSpace(s)
	if len(original) < len(passboltSchemePrefix) || !strings.EqualFold(original[:len(passboltSchemePrefix)], passboltSchemePrefix) {
		return PassboltRef{}, fmt.Errorf("expected scheme 'passbolt'")
	}
	withoutScheme := original[len(passboltSchemePrefix):]
	if strings.ContainsAny(withoutScheme, "?#") {
		return PassboltRef{}, fmt.Errorf("passbolt reference must not include a query or fragment")
	}

	escapedResource, escapedFieldPath, ok := strings.Cut(withoutScheme, "/")
	if !ok || escapedResource == "" || escapedFieldPath == "" {
		return PassboltRef{}, fmt.Errorf("expected passbolt://<ref>/<field>")
	}

	resource, err := url.PathUnescape(escapedResource)
	if err != nil {
		return PassboltRef{}, fmt.Errorf("invalid ref escaping: %w", err)
	}
	if strings.TrimSpace(resource) == "" {
		return PassboltRef{}, fmt.Errorf("expected passbolt://<ref>/<field>")
	}

	parts, err := parseEscapedPathSegments(escapedFieldPath)
	if err != nil {
		return PassboltRef{}, err
	}

	ref := PassboltRef{
		ResourceKind: resourceKind(resource),
		Resource:     resource,
	}

	switch parts[0] {
	case string(FieldName):
		return singleSegmentRef(ref, parts, FieldName)
	case string(FieldPassword):
		return singleSegmentRef(ref, parts, FieldPassword)
	case string(FieldUsername):
		return singleSegmentRef(ref, parts, FieldUsername)
	case string(FieldURI):
		return singleSegmentRef(ref, parts, FieldURI)
	case string(FieldURL):
		return singleSegmentRef(ref, parts, FieldURL)
	case string(FieldDesc):
		return singleSegmentRef(ref, parts, FieldDesc)
	case string(FieldTOTP):
		return singleSegmentRef(ref, parts, FieldTOTP)
	case string(FieldCustom):
		if len(parts) != 2 {
			return PassboltRef{}, fmt.Errorf("custom field requires exactly one field name")
		}
		if strings.TrimSpace(parts[1]) == "" {
			return PassboltRef{}, fmt.Errorf("custom field name cannot be empty")
		}
		ref.Field = FieldCustom
		ref.CustomField = parts[1]
		return ref, nil
	default:
		return PassboltRef{}, fmt.Errorf("unknown field %q", parts[0])
	}
}

func singleSegmentRef(ref PassboltRef, parts []string, field FieldKind) (PassboltRef, error) {
	if len(parts) != 1 {
		return PassboltRef{}, fmt.Errorf("%s field does not accept extra path segments", field)
	}
	ref.Field = field
	return ref, nil
}

func parseEscapedPathSegments(escapedPath string) ([]string, error) {
	rawParts := strings.Split(escapedPath, "/")
	parts := make([]string, 0, len(rawParts))

	for _, rawPart := range rawParts {
		if rawPart == "" {
			return nil, fmt.Errorf("path contains an empty segment")
		}
		part, err := url.PathUnescape(rawPart)
		if err != nil {
			return nil, fmt.Errorf("invalid path escaping: %w", err)
		}
		parts = append(parts, part)
	}
	return parts, nil
}

func resourceKind(resource string) RefKind {
	if err := uuid.Validate(resource); err == nil {
		return RefUUID
	}
	return RefName
}
