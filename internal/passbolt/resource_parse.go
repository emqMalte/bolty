package passbolt

import (
	"encoding/json"
	"strings"

	passboltapi "github.com/emqmalte/bolty/generated/passbolt"
)

type resourceEnvelope struct {
	IsV5               bool
	RawMetadataKeyType string
	MetadataKeyType    string
	MetadataKeyID      string
}

func parseResourceEnvelope(raw []byte) (resourceEnvelope, error) {
	var probe struct {
		MetadataKeyType *string `json:"metadata_key_type"`
		MetadataKeyID   *string `json:"metadata_key_id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return resourceEnvelope{}, err
	}
	env := resourceEnvelope{}
	if probe.MetadataKeyType != nil {
		env.RawMetadataKeyType = strings.TrimSpace(*probe.MetadataKeyType)
	}
	if probe.MetadataKeyID != nil {
		env.MetadataKeyID = strings.TrimSpace(*probe.MetadataKeyID)
	}
	env.IsV5 = env.RawMetadataKeyType != "" ||
		(env.MetadataKeyID != "" && !isZeroUUID(env.MetadataKeyID))
	env.MetadataKeyType = normalizeMetadataKeyType(env.RawMetadataKeyType, env.MetadataKeyID)
	return env, nil
}

func metadataKeyParams(raw []byte, v5 passboltapi.ResourceV5IndexAndView) (env resourceEnvelope, err error) {
	env, err = parseResourceEnvelope(raw)
	if err != nil {
		return env, err
	}
	if env.RawMetadataKeyType == "" && v5.MetadataKeyType != "" {
		env.RawMetadataKeyType = string(v5.MetadataKeyType)
	}
	if env.MetadataKeyID == "" || isZeroUUID(env.MetadataKeyID) {
		env.MetadataKeyID = v5.MetadataKeyId.String()
	}
	env.MetadataKeyType = normalizeMetadataKeyType(env.RawMetadataKeyType, env.MetadataKeyID)
	return env, nil
}

func resourceTypeSlug(resourceType *passboltapi.ResourceType) string {
	if resourceType == nil {
		return ""
	}
	return string(resourceType.Slug)
}
