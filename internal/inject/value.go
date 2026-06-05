package inject

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/emqmalte/bolty/internal/passbolt"
)

func passboltRefValue(resource passbolt.DecryptedResource, ref PassboltRef) (string, error) {
	switch ref.Field {
	case FieldName:
		if value := resourceName(resource); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain a name", resourceIDForError(resource, ref))
	case FieldPassword:
		if value, ok := firstSecretField(resource.Secrets, "password"); ok {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain a password", resourceIDForError(resource, ref))
	case FieldUsername:
		if value, ok := stringField(resource.Metadata, "username"); ok {
			return value, nil
		}
		if value, ok := firstSecretField(resource.Secrets, "username"); ok {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain a username", resourceIDForError(resource, ref))
	case FieldURI:
		if value, ok := resourceURI(resource); ok {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain a uri", resourceIDForError(resource, ref))
	case FieldURL:
		if value, ok := resourceURI(resource); ok {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain a url", resourceIDForError(resource, ref))
	case FieldDesc:
		if value, ok := metadataOrSecretField(resource, "description"); ok {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain a description", resourceIDForError(resource, ref))
	case FieldTOTP:
		if value, ok := metadataOrSecretField(resource, "totp"); ok {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain a totp", resourceIDForError(resource, ref))
	case FieldCustom:
		if value, ok := customFieldValue(resource.Metadata, resource.Secrets, ref.CustomField); ok {
			return value, nil
		}
		return "", fmt.Errorf("resource %s does not contain custom field %q", resourceIDForError(resource, ref), ref.CustomField)
	default:
		return "", fmt.Errorf("unsupported field kind %q", ref.Field)
	}
}

func resourceName(resource passbolt.DecryptedResource) string {
	if strings.TrimSpace(resource.DecryptedName) != "" {
		return resource.DecryptedName
	}
	if value, ok := stringField(resource.Metadata, "name"); ok {
		return value
	}
	if value, ok := stringField(resource.Metadata, "title"); ok {
		return value
	}
	return ""
}

func metadataOrSecretField(resource passbolt.DecryptedResource, key string) (string, bool) {
	if value, ok := stringField(resource.Metadata, key); ok {
		return value, true
	}
	return firstSecretField(resource.Secrets, key)
}

func resourceIDForError(resource passbolt.DecryptedResource, ref PassboltRef) string {
	if strings.TrimSpace(resource.ID) != "" {
		return resource.ID
	}
	return ref.Resource
}

func firstSecretField(secrets []any, key string) (string, bool) {
	for _, secret := range secrets {
		switch typed := secret.(type) {
		case map[string]any:
			if value, ok := stringField(typed, key); ok {
				return value, true
			}
		case string:
			if key == "password" {
				return typed, true
			}
		}
	}
	return "", false
}

func resourceURI(resource passbolt.DecryptedResource) (string, bool) {
	if value, ok := nonEmptyStringField(resource.Metadata, "uri"); ok {
		return value, true
	}
	if value, ok := firstStringInField(resource.Metadata, "uris"); ok {
		return value, true
	}

	for _, secret := range resource.Secrets {
		secretMap, ok := secret.(map[string]any)
		if !ok {
			continue
		}
		if value, ok := nonEmptyStringField(secretMap, "uri"); ok {
			return value, true
		}
		if value, ok := firstStringInField(secretMap, "uris"); ok {
			return value, true
		}
	}

	return "", false
}

// Passbolt v5 stores custom field labels in metadata and secret values in secrets.
// The shared field id connects those two halves.
func customFieldValue(metadata map[string]any, secrets []any, name string) (string, bool) {
	if value, ok := customFieldMapValue(metadata, name); ok {
		return value, true
	}

	metadataField, ok := customFieldByName(metadata, name)
	if !ok {
		return customFieldValueByName(secrets, name)
	}

	if value, ok := customFieldStoredValue(metadataField); ok {
		return value, true
	}

	if fieldID, ok := customFieldID(metadataField); ok {
		if value, ok := customFieldValueByID(secrets, fieldID); ok {
			return value, true
		}
	}
	return customFieldValueByName(secrets, name)
}

func customFieldMapValue(payload map[string]any, name string) (string, bool) {
	if payload == nil {
		return "", false
	}

	customFields, ok := payload["custom_fields"].(map[string]any)
	if !ok {
		return "", false
	}
	return stringField(customFields, name)
}

func customFieldByName(payload map[string]any, name string) (map[string]any, bool) {
	for _, field := range customFieldObjects(payload) {
		if fieldName, ok := customFieldName(field); ok && fieldName == name {
			return field, true
		}
	}
	return nil, false
}

func customFieldValueByName(secrets []any, name string) (string, bool) {
	for _, secret := range secrets {
		secretMap, ok := secret.(map[string]any)
		if !ok {
			continue
		}

		field, ok := customFieldByName(secretMap, name)
		if !ok {
			continue
		}
		if value, ok := customFieldStoredValue(field); ok {
			return value, true
		}
	}
	return "", false
}

func customFieldValueByID(secrets []any, id string) (string, bool) {
	for _, secret := range secrets {
		secretMap, ok := secret.(map[string]any)
		if !ok {
			continue
		}

		field, ok := customFieldByID(secretMap, id)
		if !ok {
			continue
		}
		if value, ok := customFieldStoredValue(field); ok {
			return value, true
		}
	}
	return "", false
}

func customFieldByID(payload map[string]any, id string) (map[string]any, bool) {
	for _, field := range customFieldObjects(payload) {
		if fieldID, ok := customFieldID(field); ok && fieldID == id {
			return field, true
		}
	}
	return nil, false
}

func customFieldObjects(payload map[string]any) []map[string]any {
	if payload == nil {
		return nil
	}

	rawFields, ok := payload["custom_fields"].([]any)
	if !ok {
		return nil
	}

	fields := make([]map[string]any, 0, len(rawFields))
	for _, rawField := range rawFields {
		field, ok := rawField.(map[string]any)
		if ok {
			fields = append(fields, field)
		}
	}
	return fields
}

func customFieldName(field map[string]any) (string, bool) {
	for _, key := range []string{"name", "metadata_key", "key", "label"} {
		if value, ok := stringField(field, key); ok {
			return value, true
		}
	}
	return "", false
}

func customFieldID(field map[string]any) (string, bool) {
	return stringField(field, "id")
}

func customFieldStoredValue(field map[string]any) (string, bool) {
	for _, key := range []string{"value", "secret_value", "data"} {
		if value, ok := stringField(field, key); ok {
			return value, true
		}
	}
	return "", false
}

func nonEmptyStringField(values map[string]any, key string) (string, bool) {
	value, ok := stringField(values, key)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func firstStringInField(values map[string]any, key string) (string, bool) {
	raw, ok := values[key]
	if !ok {
		return "", false
	}

	switch typed := raw.(type) {
	case []any:
		for _, item := range typed {
			if value, ok := valueAsString(item); ok && strings.TrimSpace(value) != "" {
				return value, true
			}
		}
	case []string:
		for _, value := range typed {
			if strings.TrimSpace(value) != "" {
				return value, true
			}
		}
	}

	return "", false
}

func stringField(values map[string]any, key string) (string, bool) {
	value, ok := values[key]
	if !ok {
		return "", false
	}
	return valueAsString(value)
}

func valueAsString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case fmt.Stringer:
		return typed.String(), true
	case []byte:
		return string(typed), true
	case bool:
		return strconv.FormatBool(typed), true
	case int:
		return strconv.Itoa(typed), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	default:
		return "", false
	}
}
