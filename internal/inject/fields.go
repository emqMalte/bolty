package inject

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/emqmalte/bolty/internal/passbolt"
)

type InjectableField struct {
	Selector string
	Label    string
}

func FieldValue(resource passbolt.DecryptedResource, selector string) (string, error) {
	ref, err := ParsePassboltRef(passboltSchemePrefix + resource.ID + "/" + escapeSelector(selector))
	if err != nil {
		return "", err
	}
	return passboltRefValue(resource, ref)
}

func AvailableFields(resource passbolt.DecryptedResource) []InjectableField {
	fields := make([]InjectableField, 0, 8)
	for _, candidate := range []struct {
		kind  FieldKind
		label string
	}{
		{FieldName, "Name"},
		{FieldUsername, "Username"},
		{FieldPassword, "Password"},
		{FieldURI, "URI (url alias available)"},
		{FieldDesc, "Description"},
		{FieldTOTP, "TOTP"},
	} {
		if candidate.kind == FieldTOTP {
			if _, ok := TOTPInfoAt(resource, time.Now()); ok {
				fields = append(fields, InjectableField{
					Selector: string(candidate.kind),
					Label:    candidate.label,
				})
			}
			continue
		}
		ref := PassboltRef{Resource: resource.ID, Field: candidate.kind}
		if value, err := passboltRefValue(resource, ref); err == nil && strings.TrimSpace(value) != "" {
			fields = append(fields, InjectableField{
				Selector: string(candidate.kind),
				Label:    candidate.label,
			})
		}
	}

	for _, name := range customFieldNames(resource) {
		ref := PassboltRef{
			Resource:    resource.ID,
			Field:       FieldCustom,
			CustomField: name,
		}
		if value, err := passboltRefValue(resource, ref); err == nil && strings.TrimSpace(value) != "" {
			fields = append(fields, InjectableField{
				Selector: "custom/" + name,
				Label:    "Custom: " + name,
			})
		}
	}
	return fields
}

func BuildPlaceholder(resourceID, selector string) (string, error) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceKind(resourceID) != RefUUID {
		return "", fmt.Errorf("resource id must be a UUID")
	}

	var parts []string
	switch {
	case strings.HasPrefix(selector, string(FieldCustom)+"/"):
		name := strings.TrimPrefix(selector, string(FieldCustom)+"/")
		if strings.TrimSpace(name) == "" {
			return "", fmt.Errorf("invalid injectable field selector %q", selector)
		}
		parts = []string{string(FieldCustom), name}
	case !strings.Contains(selector, "/"):
		parts = []string{selector}
		if _, err := ParsePassboltRef(passboltSchemePrefix + resourceID + "/" + selector); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("invalid injectable field selector %q", selector)
	}

	escaped := make([]string, len(parts))
	for i, part := range parts {
		escaped[i] = url.PathEscape(part)
	}
	reference := passboltSchemePrefix + resourceID + "/" + strings.Join(escaped, "/")
	if _, err := ParsePassboltRef(reference); err != nil {
		return "", err
	}
	return "{{ " + reference + " }}", nil
}

func escapeSelector(selector string) string {
	if strings.HasPrefix(selector, string(FieldCustom)+"/") {
		return string(FieldCustom) + "/" + url.PathEscape(strings.TrimPrefix(selector, string(FieldCustom)+"/"))
	}
	return url.PathEscape(selector)
}

func customFieldNames(resource passbolt.DecryptedResource) []string {
	names := map[string]struct{}{}
	collectCustomFieldNames(resource.Metadata, names)
	for _, secret := range resource.Secrets {
		if payload, ok := secret.(map[string]any); ok {
			collectCustomFieldNames(payload, names)
		}
	}

	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func collectCustomFieldNames(payload map[string]any, names map[string]struct{}) {
	if payload == nil {
		return
	}
	if fields, ok := payload["custom_fields"].(map[string]any); ok {
		for name := range fields {
			if strings.TrimSpace(name) != "" {
				names[name] = struct{}{}
			}
		}
	}
	for _, field := range customFieldObjects(payload) {
		if name, ok := customFieldName(field); ok && strings.TrimSpace(name) != "" {
			names[name] = struct{}{}
		}
	}
}
