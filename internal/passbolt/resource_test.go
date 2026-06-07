package passbolt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	passboltapi "github.com/emqmalte/bolty/generated/passbolt"
)

func TestGeneratedIndexResourcesRequestContainsResourceType(t *testing.T) {
	t.Parallel()

	req, err := passboltapi.NewIndexResourcesRequest("https://passbolt.test", indexResourcesParams())
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.Query().Get("contain[resource-type]"); got != "1" {
		t.Fatalf("unexpected resource type contain param: %q", got)
	}
}

func TestFolderResourceIndexRequestFiltersRoot(t *testing.T) {
	t.Parallel()

	params, editor, err := folderResourceIndexRequest("")
	if err != nil {
		t.Fatal(err)
	}
	req, err := passboltapi.NewIndexResourcesRequest("https://passbolt.test", params)
	if err != nil {
		t.Fatal(err)
	}
	if err := editor(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.URL.Query()["filter[has-parent][]"]; len(got) != 1 || got[0] != "false" {
		t.Fatalf("unexpected root parent filter: %#v", got)
	}
}

func TestFolderResourceIndexRequestFiltersFolder(t *testing.T) {
	t.Parallel()

	const folderID = "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88"
	params, editor, err := folderResourceIndexRequest(folderID)
	if err != nil {
		t.Fatal(err)
	}
	if editor != nil {
		t.Fatal("folder request should not need a custom editor")
	}
	req, err := passboltapi.NewIndexResourcesRequest("https://passbolt.test", params)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.Query().Get("filter[has-parent]"); got != folderID {
		t.Fatalf("unexpected folder parent filter: %q", got)
	}
}

func TestResourceServiceDecryptsV4Resource(t *testing.T) {
	t.Parallel()

	key := testKey(t, "Ada", "ada@example.test")
	public, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewPGPService().EncryptAndSign([]byte(`{"password":"s3cr3t"}`), public, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseUUID("ae60d89c-f13b-4fb1-b2dc-c8dc806cac88")
	if err != nil {
		t.Fatal(err)
	}
	userID, err := parseUUID("8bb80df5-700c-48ce-b568-85a60fc3c8f2")
	if err != nil {
		t.Fatal(err)
	}
	secrets := []passboltapi.SecretIndex{{
		Id:         id,
		ResourceId: id,
		UserId:     userID,
		Data:       secret,
		Created:    time.Unix(1, 0),
		Modified:   time.Unix(1, 0),
	}}
	resource, err := NewResourceService(newMemorySecretStore()).decryptV4(passboltapi.ResourceV4IndexAndView{
		Id:       id,
		Name:     "database",
		Username: "db-user",
		Uri:      "postgres://db",
		Secrets:  &secrets,
	}, key, userID.String())
	if err != nil {
		t.Fatal(err)
	}
	if resource.DecryptedName != "database" {
		t.Fatalf("unexpected name: %q", resource.DecryptedName)
	}
	if len(resource.Secrets) != 1 {
		t.Fatalf("unexpected secrets: %#v", resource.Secrets)
	}
	secretMap, ok := resource.Secrets[0].(map[string]any)
	if !ok || secretMap["password"] != "s3cr3t" {
		t.Fatalf("unexpected decrypted secret: %#v", resource.Secrets[0])
	}
}

func TestMatchingV4SecretsPrefersCurrentUser(t *testing.T) {
	t.Parallel()

	resourceID, err := parseUUID("ae60d89c-f13b-4fb1-b2dc-c8dc806cac88")
	if err != nil {
		t.Fatal(err)
	}
	currentUser, err := parseUUID("8bb80df5-700c-48ce-b568-85a60fc3c8f2")
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := parseUUID("210ceac8-e4ea-467d-9c20-102b21c7e7ab")
	if err != nil {
		t.Fatal(err)
	}
	secrets := []passboltapi.SecretIndex{
		{Id: resourceID, ResourceId: resourceID, UserId: otherUser, Data: "other"},
		{Id: resourceID, ResourceId: resourceID, UserId: currentUser, Data: "current"},
	}
	matches := matchingV4Secrets(secrets, currentUser.String())
	if len(matches) != 1 || matches[0].Data != "current" {
		t.Fatalf("unexpected matches: %#v", matches)
	}
	matches = matchingV4Secrets(secrets[:1], currentUser.String())
	if len(matches) != 1 || matches[0].Data != "other" {
		t.Fatalf("expected single available secret to be used when user id does not match, got %#v", matches)
	}
}

func TestDecryptedResourceJSONOmitsRawResource(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(DecryptedResource{
		ID:          "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
		Type:        "v4",
		RawResource: map[string]any{"encrypted": "payload"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "raw_resource") {
		t.Fatalf("raw_resource should not be in default JSON output: %s", data)
	}
}

func TestGetByNameRequiresExactDecryptedNameMatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resources.json" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		writeResourceIndexResponse(t, w, []map[string]any{{
			"id":   "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
			"name": "Similar Name",
		}})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewResourceService(newMemorySecretStore()).getByName(context.Background(), client, "Exact Name", nil, "")
	if !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected resource not found, got %v", err)
	}
	if !strings.Contains(err.Error(), "no resource exactly named") || !strings.Contains(err.Error(), "unique UUID") {
		t.Fatalf("expected exact-name and UUID guidance, got %v", err)
	}
}

func TestGetByNameReportsAmbiguousExactMatches(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resources.json" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		writeResourceIndexResponse(t, w, []map[string]any{
			{
				"id":   "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
				"name": "Exact Name",
			},
			{
				"id":   "f1b79505-2371-422f-88d8-9c6326806b3d",
				"name": "Exact Name",
			},
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewResourceService(newMemorySecretStore()).getByName(context.Background(), client, "Exact Name", nil, "")
	if !errors.Is(err, ErrResourceNameAmbiguous) {
		t.Fatalf("expected ambiguous resource name, got %v", err)
	}
	if !strings.Contains(err.Error(), "matches multiple resources") || !strings.Contains(err.Error(), "unique UUID") {
		t.Fatalf("expected ambiguity and UUID guidance, got %v", err)
	}
}

func writeResourceIndexResponse(t *testing.T, w http.ResponseWriter, body []map[string]any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"header": map[string]any{
			"status": "success",
		},
		"body": body,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDecryptV4SecretIndicesTriesAlternateCopies(t *testing.T) {
	t.Parallel()

	owner := testKey(t, "Owner", "owner@example.test")
	viewer := testKey(t, "Viewer", "viewer@example.test")
	ownerPublic, err := owner.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	viewerPublic, err := viewer.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	viewerSecret, err := NewPGPService().EncryptAndSign([]byte(`{"password":"viewer-secret"}`), viewerPublic, viewer)
	if err != nil {
		t.Fatal(err)
	}
	ownerSecret, err := NewPGPService().EncryptAndSign([]byte(`{"password":"owner-secret"}`), ownerPublic, owner)
	if err != nil {
		t.Fatal(err)
	}
	resourceID, err := parseUUID("ae60d89c-f13b-4fb1-b2dc-c8dc806cac88")
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := parseUUID("210ceac8-e4ea-467d-9c20-102b21c7e7ab")
	if err != nil {
		t.Fatal(err)
	}
	viewerID, err := parseUUID("8bb80df5-700c-48ce-b568-85a60fc3c8f2")
	if err != nil {
		t.Fatal(err)
	}
	indices := []passboltapi.SecretIndex{
		{Id: resourceID, ResourceId: resourceID, UserId: ownerID, Data: ownerSecret},
		{Id: resourceID, ResourceId: resourceID, UserId: viewerID, Data: viewerSecret},
	}
	secrets, err := NewResourceService(newMemorySecretStore()).decryptSecretIndices(indices, viewer, viewerID.String(), resourceID.String())
	if err != nil {
		t.Fatal(err)
	}
	if !hasUsableSecrets(secrets) {
		t.Fatalf("expected decrypted secret, got %#v", secrets)
	}
	secretMap, ok := secrets[0].(map[string]any)
	if !ok || secretMap["password"] != "viewer-secret" {
		t.Fatalf("unexpected decrypted secret: %#v", secrets[0])
	}
}

func TestAlternateMetadataKeyType(t *testing.T) {
	t.Parallel()

	if alternateMetadataKeyType("user_key") != "shared_key" {
		t.Fatal("expected user_key to alternate to shared_key")
	}
	if alternateMetadataKeyType("shared_key") != "user_key" {
		t.Fatal("expected shared_key to alternate to user_key")
	}
}

func TestSecretPayloadFromMetadataFindsNestedPassword(t *testing.T) {
	t.Parallel()

	payload := secretPayloadFromMetadata(map[string]any{
		"object_type": "PASSBOLT_RESOURCE_METADATA",
		"resource": map[string]any{
			"name": "Test Password 1",
		},
		"custom_fields": []any{
			map[string]any{"metadata_key": "token"},
		},
	})
	if payload != nil {
		t.Fatalf("expected no direct password payload, got %#v", payload)
	}
	payload = secretPayloadFromMetadata(map[string]any{
		"password": "from-metadata",
		"nested": map[string]any{
			"totp": map[string]any{
				"secret_key": "DAV3DS4ERAAF5QGH",
				"period":     float64(30),
				"digits":     float64(6),
				"algorithm":  "SHA1",
			},
		},
	})
	totp, ok := payload["totp"].(map[string]any)
	if payload["password"] != "from-metadata" || !ok || totp["secret_key"] != "DAV3DS4ERAAF5QGH" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestNormalizeMetadataKeyType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		keyType string
		keyID   string
		want    string
	}{
		{keyType: "user_key", keyID: "0194fec1-65fa-7b6f-935a-9541c1c13281", want: "user_key"},
		{keyType: "shared_key", keyID: "0194fec1-65fa-7b6f-935a-9541c1c13281", want: "shared_key"},
		{keyType: "", keyID: "0194fec1-65fa-7b6f-935a-9541c1c13281", want: "shared_key"},
		{keyType: "", keyID: "", want: "user_key"},
	}
	for _, tt := range tests {
		if got := normalizeMetadataKeyType(tt.keyType, tt.keyID); got != tt.want {
			t.Fatalf("normalizeMetadataKeyType(%q, %q) = %q, want %q", tt.keyType, tt.keyID, got, tt.want)
		}
	}
}

func TestParseResourceEnvelopeDetectsV5(t *testing.T) {
	t.Parallel()

	env, err := parseResourceEnvelope([]byte(`{"name":"legacy","metadata_key_type":"shared_key"}`))
	if err != nil || !env.IsV5 {
		t.Fatal("expected metadata_key_type to identify v5 resources")
	}
	env, err = parseResourceEnvelope([]byte(`{"name":"legacy","metadata_key_id":"0194fec1-65fa-7b6f-935a-9541c1c13281"}`))
	if err != nil || !env.IsV5 {
		t.Fatal("expected metadata_key_id to identify v5 resources")
	}
	env, err = parseResourceEnvelope([]byte(`{"name":"legacy","username":"ada"}`))
	if err != nil || env.IsV5 {
		t.Fatal("expected legacy v4 resource json to stay v4")
	}
}

func TestUnmarshalV5ResourceAcceptsSecretIndexObjects(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"id":"ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
		"metadata_key_type":"user_key",
		"metadata_key_id":"0194fec1-65fa-7b6f-935a-9541c1c13281",
		"metadata":"-----BEGIN PGP MESSAGE-----",
		"secrets":[{"id":"f1b79505-2371-422f-88d8-9c6326806b3d","user_id":"8bb80df5-700c-48ce-b568-85a60fc3c8f2","data":"-----BEGIN PGP MESSAGE-----"}],
		"created":"1970-01-01T00:00:00Z",
		"modified":"1970-01-01T00:00:00Z",
		"created_by":"8bb80df5-700c-48ce-b568-85a60fc3c8f2",
		"modified_by":"8bb80df5-700c-48ce-b568-85a60fc3c8f2",
		"resource_type_id":"4bd2c10d-58bd-4ce3-9082-2513dee924ff",
		"folder_parent_id":"00000000-0000-0000-0000-000000000000",
		"expired":"1970-01-01T00:00:00Z",
		"deleted":false,
		"personal":true
	}`)
	var body passboltapi.ResourcesView_Body
	if err := body.UnmarshalJSON(raw); err != nil {
		t.Fatalf("view body unmarshal: %v", err)
	}
	_, secretsJSON, err := unmarshalV5Resource(raw)
	if err != nil {
		t.Fatalf("unmarshalV5Resource: %v", err)
	}
	var indices []passboltapi.SecretIndex
	if err := json.Unmarshal(secretsJSON, &indices); err != nil {
		t.Fatalf("secrets field is not secretIndex objects: %v", err)
	}
	if len(indices) != 1 {
		t.Fatalf("unexpected secret count: %d", len(indices))
	}
}

func TestDecryptViewBodyTreatsMetadataKeyTypeAsV5(t *testing.T) {
	t.Parallel()

	key := testKey(t, "Ada", "ada@example.test")
	public, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	metadataArmored, err := NewPGPService().EncryptAndSign([]byte(`{"name":"Test Password 1"}`), public, key)
	if err != nil {
		t.Fatal(err)
	}
	id := "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88"
	keyID := "0194fec1-65fa-7b6f-935a-9541c1c13281"
	raw := []byte(`{
		"id":"` + id + `",
		"metadata_key_type":"user_key",
		"metadata_key_id":"` + keyID + `",
		"metadata":` + strconvQuote(metadataArmored) + `,
		"secrets":["{\"password\":\"s3cr3t\"}"],
		"created":"1970-01-01T00:00:00Z",
		"modified":"1970-01-01T00:00:00Z",
		"created_by":"8bb80df5-700c-48ce-b568-85a60fc3c8f2",
		"modified_by":"8bb80df5-700c-48ce-b568-85a60fc3c8f2",
		"resource_type_id":"4bd2c10d-58bd-4ce3-9082-2513dee924ff",
		"folder_parent_id":"00000000-0000-0000-0000-000000000000",
		"expired":"1970-01-01T00:00:00Z",
		"deleted":false,
		"personal":true
	}`)
	var body passboltapi.ResourcesView_Body
	if err := body.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	resource, err := NewResourceService(newMemorySecretStore()).decryptViewBody(context.Background(), nil, body, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if resource.Type != "v5" {
		t.Fatalf("expected v5 resource, got %q", resource.Type)
	}
	if resource.DecryptedName != "Test Password 1" {
		t.Fatalf("unexpected name: %q", resource.DecryptedName)
	}
	if !hasUsableSecrets(resource.Secrets) {
		t.Fatalf("expected decrypted secret, got %#v", resource.Secrets)
	}
}

func strconvQuote(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestResourceServiceDecryptsV5UserKeyMetadata(t *testing.T) {
	t.Parallel()

	key := testKey(t, "Ada", "ada@example.test")
	public, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := NewPGPService().EncryptAndSign([]byte(`{"name":"api","custom_fields":[{"name":"env","value":"prod"}]}`), public, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseUUID("ae60d89c-f13b-4fb1-b2dc-c8dc806cac88")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := parseUUID("0194fec1-65fa-7b6f-935a-9541c1c13281")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := NewResourceService(newMemorySecretStore()).decryptV5(context.Background(), nil, passboltapi.ResourceV5IndexAndView{
		Id:              id,
		Metadata:        metadata,
		MetadataKeyId:   keyID,
		MetadataKeyType: passboltapi.ResourceV5IndexAndViewMetadataKeyTypeUserKey,
	}, nil, resourceEnvelope{
		RawMetadataKeyType: "user_key",
		MetadataKeyType:    "user_key",
		MetadataKeyID:      keyID.String(),
	}, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if resource.DecryptedName != "api" {
		t.Fatalf("unexpected name: %q", resource.DecryptedName)
	}
	if _, ok := resource.Metadata["custom_fields"]; !ok {
		t.Fatalf("custom fields were not preserved: %#v", resource.Metadata)
	}
}

func TestMatchingMetadataPrivateKeysPrefersCurrentUser(t *testing.T) {
	t.Parallel()

	currentUser := "8bb80df5-700c-48ce-b568-85a60fc3c8f2"
	keys := []passboltapi.MetadataPrivateKeysIndexAndView{
		{UserId: "210ceac8-e4ea-467d-9c20-102b21c7e7ab", Data: "other"},
		{UserId: currentUser, Data: "current"},
	}
	matches := matchingMetadataPrivateKeys(keys, currentUser)
	if len(matches) != 1 || matches[0].Data != "current" {
		t.Fatalf("unexpected matches: %#v", matches)
	}
}

func TestResourceIDAndNameFromV4Index(t *testing.T) {
	t.Parallel()

	id, err := parseUUID("ae60d89c-f13b-4fb1-b2dc-c8dc806cac88")
	if err != nil {
		t.Fatal(err)
	}
	item := passboltapi.ResourcesIndex_Body_Item{}
	if err := item.FromResourceV4IndexAndView(passboltapi.ResourceV4IndexAndView{
		Id:   id,
		Name: "Test Password 1",
	}); err != nil {
		t.Fatal(err)
	}
	gotID, gotName, err := NewResourceService(newMemorySecretStore()).resourceIDAndName(context.Background(), nil, item, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id.String() || gotName != "Test Password 1" {
		t.Fatalf("resourceIDAndName() = (%q, %q), want (%q, %q)", gotID, gotName, id.String(), "Test Password 1")
	}
}

func TestResourceIDAndNameFromV5IndexMetadata(t *testing.T) {
	t.Parallel()

	key := testKey(t, "Ada", "ada@example.test")
	public, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := NewPGPService().EncryptAndSign([]byte(`{"name":"Test Password 1"}`), public, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseUUID("ae60d89c-f13b-4fb1-b2dc-c8dc806cac88")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := parseUUID("0194fec1-65fa-7b6f-935a-9541c1c13281")
	if err != nil {
		t.Fatal(err)
	}
	item := passboltapi.ResourcesIndex_Body_Item{}
	if err := item.FromResourceV5IndexAndView(passboltapi.ResourceV5IndexAndView{
		Id:              id,
		Metadata:        metadata,
		MetadataKeyId:   keyID,
		MetadataKeyType: passboltapi.ResourceV5IndexAndViewMetadataKeyTypeUserKey,
	}); err != nil {
		t.Fatal(err)
	}
	gotID, gotName, err := NewResourceService(newMemorySecretStore()).resourceIDAndName(context.Background(), nil, item, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id.String() || gotName != "Test Password 1" {
		t.Fatalf("resourceIDAndName() = (%q, %q), want (%q, %q)", gotID, gotName, id.String(), "Test Password 1")
	}
}

func TestHasUsableSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		secrets []any
		want    bool
	}{
		{
			name:    "empty",
			secrets: nil,
			want:    false,
		},
		{
			name: "encrypted placeholder only",
			secrets: []any{map[string]any{
				"encrypted": true,
				"data":      "-----BEGIN PGP MESSAGE-----",
			}},
			want: false,
		},
		{
			name:    "decrypted value",
			secrets: []any{map[string]any{"password": "secret"}},
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasUsableSecrets(tt.secrets); got != tt.want {
				t.Fatalf("hasUsableSecrets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSummaryFromMetadataOmitsSecretFields(t *testing.T) {
	t.Parallel()

	summary := summaryFromMetadata("id", "v5", "password-string", map[string]any{
		"name":        "postgres-prod",
		"username":    "ada",
		"uri":         "postgres.example.test",
		"description": "database",
		"password":    "must-not-leak",
		"totp":        "otpauth://totp/test",
	})
	if summary.Name != "postgres-prod" || summary.Username != "ada" || summary.URI != "postgres.example.test" || summary.Description != "database" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "must-not-leak") || strings.Contains(string(data), "otpauth") {
		t.Fatalf("summary leaked secret material: %s", data)
	}
	if !summaryMatches(summary, "postgres") || !summaryMatches(summary, "database") {
		t.Fatalf("summary should match visible fields: %#v", summary)
	}
}

func TestSummaryFromMetadataUsesPrimaryAndPreservesAdditionalURIs(t *testing.T) {
	t.Parallel()

	summary := summaryFromMetadata("id", "v5", "password-string", map[string]any{
		"name": "api",
		"uris": []any{"https://primary.test", "https://secondary.test"},
	})
	if summary.URI != "https://primary.test" || summary.URL != "https://primary.test" {
		t.Fatalf("unexpected primary URI: %#v", summary)
	}
	if got := strings.Join(summary.URIs, ","); got != "https://primary.test,https://secondary.test" {
		t.Fatalf("unexpected URI collection: %q", got)
	}
	if !summaryMatches(summary, "secondary.test") {
		t.Fatal("summary search should include additional URIs")
	}
}

func TestResourceURIsSupportsLegacyAndNestedMetadata(t *testing.T) {
	t.Parallel()

	got := ResourceURIs(map[string]any{
		"resource": map[string]any{
			"uris": []string{"https://primary.test", "https://secondary.test"},
			"uri":  "https://primary.test",
		},
	}, nil)
	if value := strings.Join(got, ","); value != "https://primary.test,https://secondary.test" {
		t.Fatalf("ResourceURIs() = %q", value)
	}
}

func TestFolderBreadcrumbBuildsRootToLeafPath(t *testing.T) {
	t.Parallel()

	folders := map[string]FolderSummary{
		"root":   {ID: "root", Name: "Engineering"},
		"child":  {ID: "child", ParentID: "root", Name: "Production"},
		"nested": {ID: "nested", ParentID: "child", Name: "Databases"},
	}
	if got := folderBreadcrumb("nested", folders); got != "Engineering / Production / Databases" {
		t.Fatalf("folderBreadcrumb() = %q", got)
	}
}

func TestFolderBreadcrumbHandlesMissingFoldersAndCycles(t *testing.T) {
	t.Parallel()

	folders := map[string]FolderSummary{
		"a": {ID: "a", ParentID: "b", Name: "A"},
		"b": {ID: "b", ParentID: "a", Name: "B"},
	}
	if got := folderBreadcrumb("a", folders); got != "B / A" {
		t.Fatalf("cycle breadcrumb = %q", got)
	}
	if got := folderBreadcrumb("missing", folders); got != "" {
		t.Fatalf("missing breadcrumb = %q", got)
	}
}

func TestListFolderSummariesReadsV4Hierarchy(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/folders.json" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"header": map[string]any{"status": "success"},
			"body": []map[string]any{
				{
					"id":               "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
					"name":             "Engineering",
					"created":          "1970-01-01T00:00:00Z",
					"modified":         "1970-01-01T00:00:00Z",
					"created_by":       "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
					"modified_by":      "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
					"folder_parent_id": nil,
					"personal":         true,
				},
				{
					"id":               "f1b79505-2371-422f-88d8-9c6326806b3d",
					"name":             "Production",
					"created":          "1970-01-01T00:00:00Z",
					"modified":         "1970-01-01T00:00:00Z",
					"created_by":       "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
					"modified_by":      "8bb80df5-700c-48ce-b568-85a60fc3c8f2",
					"folder_parent_id": "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
					"personal":         true,
				},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	folders, err := NewResourceService(newMemorySecretStore()).listFolderSummaries(context.Background(), client, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	child := folders["f1b79505-2371-422f-88d8-9c6326806b3d"]
	if child.Name != "Production" || child.ParentID != "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88" {
		t.Fatalf("unexpected child folder: %#v", child)
	}
	if got := folderBreadcrumb(child.ID, folders); got != "Engineering / Production" {
		t.Fatalf("unexpected breadcrumb: %q", got)
	}
}

func TestMetadataNameReadsCommonShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]any
		want     string
	}{
		{name: "name", metadata: map[string]any{"name": "direct"}, want: "direct"},
		{name: "title", metadata: map[string]any{"title": "titled"}, want: "titled"},
		{name: "nested resource", metadata: map[string]any{"resource": map[string]any{"name": "nested"}}, want: "nested"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := metadataName(tt.metadata); got != tt.want {
				t.Fatalf("metadataName() = %q, want %q", got, tt.want)
			}
		})
	}
}
