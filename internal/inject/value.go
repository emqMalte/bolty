package inject

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- SHA-1 is required for RFC 6238 compatibility and is used only as an HMAC.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

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
		if value, ok := resourceTOTP(resource); ok {
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
	uris := passbolt.ResourceURIs(resource.Metadata, resource.Secrets)
	if len(uris) > 0 {
		return uris[0], true
	}
	return "", false
}

func resourceTOTP(resource passbolt.DecryptedResource) (string, bool) {
	status, ok := TOTPStatusAt(resource, time.Now())
	return status.Code, ok
}

type TOTPStatus struct {
	Code      string
	Digits    int
	Period    time.Duration
	ExpiresAt time.Time
}

func TOTPStatusAt(resource passbolt.DecryptedResource, now time.Time) (TOTPStatus, bool) {
	info, ok := TOTPInfoAt(resource, now)
	if !ok {
		return TOTPStatus{}, false
	}
	if info.Code != "" {
		return info, true
	}
	if status, ok := totpField(resource.Metadata, now, true); ok {
		return status, true
	}
	for _, secret := range resource.Secrets {
		payload, ok := secret.(map[string]any)
		if !ok {
			continue
		}
		if status, ok := totpField(payload, now, true); ok {
			return status, true
		}
	}
	return TOTPStatus{}, false
}

func TOTPInfoAt(resource passbolt.DecryptedResource, now time.Time) (TOTPStatus, bool) {
	if status, ok := totpField(resource.Metadata, now, false); ok {
		return status, true
	}
	for _, secret := range resource.Secrets {
		payload, ok := secret.(map[string]any)
		if !ok {
			continue
		}
		if status, ok := totpField(payload, now, false); ok {
			return status, true
		}
	}
	return TOTPStatus{}, false
}

func totpField(payload map[string]any, now time.Time, generate bool) (TOTPStatus, bool) {
	raw, ok := payload["totp"]
	if !ok {
		return TOTPStatus{}, false
	}
	if value, ok := valueAsString(raw); ok {
		value = strings.TrimSpace(value)
		if len(value) >= 6 && len(value) <= 8 && strings.IndexFunc(value, func(r rune) bool {
			return r < '0' || r > '9'
		}) == -1 {
			return TOTPStatus{Code: value, Digits: len(value)}, true
		}
		return totpCodeFromURI(value, now, generate)
	}

	totp, ok := raw.(map[string]any)
	if !ok {
		return TOTPStatus{}, false
	}
	secret, ok := stringField(totp, "secret_key")
	if !ok || strings.TrimSpace(secret) == "" {
		return TOTPStatus{}, false
	}

	algorithm := "SHA1"
	if value, ok := stringField(totp, "algorithm"); ok && strings.TrimSpace(value) != "" {
		algorithm = value
	}
	digits := 6
	if value, ok := integerField(totp, "digits"); ok {
		digits = value
	}
	period := 30
	if value, ok := integerField(totp, "period"); ok {
		period = value
	}
	return buildTOTPStatus(secret, algorithm, digits, period, now, generate)
}

func totpCodeFromURI(value string, now time.Time, generate bool) (TOTPStatus, bool) {
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "otpauth") || !strings.EqualFold(parsed.Host, "totp") {
		return TOTPStatus{}, false
	}
	query := parsed.Query()
	digits := queryInteger(query, "digits", 6)
	period := queryInteger(query, "period", 30)
	return buildTOTPStatus(query.Get("secret"), query.Get("algorithm"), digits, period, now, generate)
}

func buildTOTPStatus(secret, algorithm string, digits, period int, now time.Time, generate bool) (TOTPStatus, bool) {
	if _, _, err := totpKeyAndHash(secret, algorithm); err != nil {
		return TOTPStatus{}, false
	}
	status, err := newTOTPStatus("", digits, period, now)
	if err != nil {
		return TOTPStatus{}, false
	}
	if !generate {
		return status, true
	}
	status.Code, err = generateTOTP(secret, algorithm, digits, period, now)
	return status, err == nil
}

func newTOTPStatus(code string, digits, period int, now time.Time) (TOTPStatus, error) {
	if err := validateTOTPWindow(digits, period, now); err != nil {
		return TOTPStatus{}, err
	}
	periodDuration := time.Duration(period) * time.Second
	unix := now.Unix()
	periodSeconds := int64(period)
	untilNext := periodSeconds - unix%periodSeconds
	return TOTPStatus{
		Code:      code,
		Digits:    digits,
		Period:    periodDuration,
		ExpiresAt: time.Unix(unix+untilNext, 0),
	}, nil
}

func generateTOTP(secret, algorithm string, digits, period int, now time.Time) (string, error) {
	if err := validateTOTPWindow(digits, period, now); err != nil {
		return "", err
	}
	key, hashFunc, err := totpKeyAndHash(secret, algorithm)
	if err != nil {
		return "", err
	}

	counter := uint64(now.Unix() / int64(period)) // #nosec G115 -- validateTOTPWindow rejects negative timestamps.
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)
	mac := hmac.New(hashFunc, key)
	_, _ = mac.Write(message)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, binaryCode%modulus), nil
}

func validateTOTPWindow(digits, period int, now time.Time) error {
	if period <= 0 {
		return fmt.Errorf("invalid TOTP period %d", period)
	}
	if digits < 6 || digits > 8 {
		return fmt.Errorf("invalid TOTP digits %d", digits)
	}
	periodSeconds := int64(period)
	if periodSeconds > int64(math.MaxInt64/time.Second) {
		return fmt.Errorf("TOTP period %d is too large", period)
	}
	unix := now.Unix()
	if unix < 0 {
		return fmt.Errorf("TOTP timestamp predates the Unix epoch")
	}
	untilNext := periodSeconds - unix%periodSeconds
	if unix > math.MaxInt64-untilNext {
		return fmt.Errorf("TOTP expiry exceeds the supported time range")
	}
	return nil
}

func totpKeyAndHash(secret, algorithm string) ([]byte, func() hash.Hash, error) {
	normalizedSecret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	normalizedSecret = strings.TrimRight(normalizedSecret, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalizedSecret)
	if err != nil || len(key) == 0 {
		return nil, nil, fmt.Errorf("invalid TOTP secret")
	}

	var hashFunc func() hash.Hash
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "", "SHA1":
		hashFunc = sha1.New
	case "SHA256":
		hashFunc = sha256.New
	case "SHA512":
		hashFunc = sha512.New
	default:
		return nil, nil, fmt.Errorf("unsupported TOTP algorithm %q", algorithm)
	}
	return key, hashFunc, nil
}

func integerField(values map[string]any, key string) (int, bool) {
	value, ok := valueAsString(values[key])
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil
}

func queryInteger(values url.Values, key string, fallback int) int {
	value := strings.TrimSpace(values.Get(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
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
