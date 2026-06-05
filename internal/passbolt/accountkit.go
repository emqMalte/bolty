package passbolt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type AccountKit struct {
	ServerURL  string
	UserID     string
	Username   string
	PrivateKey string
}

func ParseAccountKitFile(path string) (AccountKit, error) {
	// #nosec G304 -- CLI users intentionally choose the account-kit path to import.
	data, err := os.ReadFile(path)
	if err != nil {
		return AccountKit{}, err
	}
	return ParseAccountKit(data)
}

func ParseAccountKit(data []byte) (AccountKit, error) {
	payload := strings.TrimSpace(string(data))
	if payload == "" {
		return AccountKit{}, errors.New("account kit is empty")
	}

	candidates := [][]byte{[]byte(payload)}
	if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil {
		candidates = append(candidates, decoded)
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(payload); err == nil {
		candidates = append(candidates, decoded)
	}

	var lastErr error
	for _, candidate := range candidates {
		candidate = unwrapClearSignedMessage(candidate)
		kit, err := parseAccountKitJSON(candidate)
		if err == nil {
			return kit, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return AccountKit{}, fmt.Errorf("unsupported account kit format: expected JSON, base64 JSON, or base64 PGP signed JSON: %w", lastErr)
	}
	return AccountKit{}, errors.New("account kit format is not supported")
}

func parseAccountKitJSON(data []byte) (AccountKit, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return AccountKit{}, err
	}
	flat := map[string]string{}
	flattenJSON("", raw, flat)

	kit := AccountKit{
		ServerURL:  firstValue(flat, "domain", "url", "server_url", "serverurl", "full_base_url", "fullbaseurl"),
		UserID:     firstValue(flat, "user_id", "userid", "id"),
		Username:   firstValue(flat, "username", "email"),
		PrivateKey: firstValue(flat, "private_key", "privatekey", "user_private_armored_key", "userprivatearmoredkey", "armored_private_key", "armoredprivatekey", "armored_key", "armoredkey"),
	}
	if kit.PrivateKey == "" {
		for _, value := range flat {
			if strings.Contains(value, "-----BEGIN PGP PRIVATE KEY BLOCK-----") {
				kit.PrivateKey = value
				break
			}
		}
	}
	if kit.ServerURL == "" || kit.UserID == "" || kit.PrivateKey == "" {
		return AccountKit{}, fmt.Errorf("account kit is missing required fields: server_url=%t user_id=%t private_key=%t", kit.ServerURL != "", kit.UserID != "", kit.PrivateKey != "")
	}
	kit.ServerURL = normalizeBaseURL(kit.ServerURL)
	return kit, nil
}

func unwrapClearSignedMessage(data []byte) []byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "-----BEGIN PGP SIGNED MESSAGE-----") {
		return data
	}
	bodyStart := strings.Index(text, "\n\n")
	if bodyStart < 0 {
		return data
	}
	body := text[bodyStart+2:]
	signatureStart := strings.Index(body, "\n-----BEGIN PGP SIGNATURE-----")
	if signatureStart >= 0 {
		body = body[:signatureStart]
	}
	body = strings.TrimSpace(body)
	body = strings.ReplaceAll(body, "\n- -", "\n-")
	return []byte(body)
}

func flattenJSON(prefix string, value any, out map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := normalizeFieldName(key)
			if prefix != "" {
				normalized = prefix + "." + normalized
			}
			flattenJSON(normalized, child, out)
		}
	case []any:
		for _, child := range typed {
			flattenJSON(prefix, child, out)
		}
	case string:
		if prefix != "" {
			out[prefix] = typed
			parts := strings.Split(prefix, ".")
			out[parts[len(parts)-1]] = typed
		}
	}
}

func firstValue(values map[string]string, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(values[normalizeFieldName(name)]); value != "" {
			return value
		}
	}
	for key, value := range values {
		for _, name := range names {
			if strings.HasSuffix(key, "."+normalizeFieldName(name)) && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func normalizeFieldName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "-", "_")
	return name
}
