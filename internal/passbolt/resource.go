package passbolt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	passboltapi "github.com/emqmalte/bolty/generated/passbolt"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

type ResourceService struct {
	Auth  AuthService
	Store SecretStore
	PGP   PGPService
	Debug io.Writer
}

type DecryptedResource struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	ResourceType  string         `json:"resource_type,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	Secrets       []any          `json:"secrets,omitempty"`
	RawResource   any            `json:"-"`
	DecryptedName string         `json:"-"`
}

type ResourceSummary struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	ResourceType   string   `json:"resource_type,omitempty"`
	Name           string   `json:"name,omitempty"`
	Username       string   `json:"username,omitempty"`
	URI            string   `json:"uri,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	URL            string   `json:"url,omitempty"`
	Description    string   `json:"description,omitempty"`
	FolderParentID string   `json:"folder_parent_id,omitempty"`
	FolderPath     string   `json:"folder_path,omitempty"`
}

type FolderSummary struct {
	ID       string `json:"id"`
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name"`
}

func NewResourceService(store SecretStore) ResourceService {
	auth := NewAuthService(store)
	return ResourceService{Auth: auth, Store: store, PGP: NewPGPService()}
}

func (s ResourceService) Get(ctx context.Context, profile Profile, idOrName string, opts ...Option) (DecryptedResource, error) {
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		return DecryptedResource{}, errors.New("resource id or name is required")
	}
	client, err := s.Auth.AuthenticatedClient(ctx, profile, opts...)
	if err != nil {
		return DecryptedResource{}, err
	}
	privateKey, err := s.Auth.unlockedPrivateKey(profile.Name)
	if err != nil {
		return DecryptedResource{}, fmt.Errorf("unlock profile private key: %w", err)
	}
	defer privateKey.ClearPrivateParams()

	if id, err := parseUUID(idOrName); err == nil {
		return s.getByID(ctx, client, id, privateKey, profile.UserID)
	}
	return s.getByName(ctx, client, idOrName, privateKey, profile.UserID)
}

func (s ResourceService) List(ctx context.Context, profile Profile, search string, opts ...Option) ([]ResourceSummary, error) {
	folders, err := s.ListFolders(ctx, profile, opts...)
	if err != nil {
		if s.Debug != nil {
			fmt.Fprintf(s.Debug, "list resources: folder paths unavailable: %v\n", err)
		}
		folders = nil
	}
	resources, err := s.listResources(ctx, profile, indexResourcesParams(), nil, folderSummaryMap(folders), opts...)
	if err != nil {
		return nil, err
	}
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return resources, nil
	}
	filtered := resources[:0]
	for _, summary := range resources {
		if summaryMatches(summary, search) {
			filtered = append(filtered, summary)
		}
	}
	return filtered, nil
}

func (s ResourceService) ListFolders(ctx context.Context, profile Profile, opts ...Option) ([]FolderSummary, error) {
	client, err := s.Auth.AuthenticatedClient(ctx, profile, opts...)
	if err != nil {
		return nil, err
	}
	privateKey, err := s.Auth.unlockedPrivateKey(profile.Name)
	if err != nil {
		return nil, fmt.Errorf("unlock profile private key: %w", err)
	}
	defer privateKey.ClearPrivateParams()

	folders, err := s.listFolderSummaries(ctx, client, privateKey, profile.UserID)
	if err != nil {
		return nil, err
	}
	result := make([]FolderSummary, 0, len(folders))
	for _, folder := range folders {
		result = append(result, folder)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ParentID != result[j].ParentID {
			return result[i].ParentID < result[j].ParentID
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result, nil
}

func (s ResourceService) ListFolder(ctx context.Context, profile Profile, parentID string, folders []FolderSummary, opts ...Option) ([]ResourceSummary, error) {
	params, editor, err := folderResourceIndexRequest(parentID)
	if err != nil {
		return nil, err
	}
	return s.listResources(ctx, profile, params, editor, folderSummaryMap(folders), opts...)
}

func folderResourceIndexRequest(parentID string) (*passboltapi.IndexResourcesParams, passboltapi.RequestEditorFn, error) {
	params := indexResourcesParams()
	parentID = nullableUUIDString(parentID)
	if parentID == "" {
		editor := func(_ context.Context, req *http.Request) error {
			query := req.URL.Query()
			query.Add("filter[has-parent][]", "false")
			req.URL.RawQuery = query.Encode()
			return nil
		}
		return params, editor, nil
	} else {
		parsed, err := parseUUID(parentID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid folder id: %w", err)
		}
		filter := passboltapi.FilterHasParent(parsed)
		params.FilterHasParent = &filter
	}
	return params, nil, nil
}

func (s ResourceService) SearchAll(ctx context.Context, profile Profile, search string, folders []FolderSummary, opts ...Option) ([]ResourceSummary, error) {
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return nil, errors.New("global resource search requires a search term")
	}
	resources, err := s.listResources(ctx, profile, indexResourcesParams(), nil, folderSummaryMap(folders), opts...)
	if err != nil {
		return nil, err
	}
	filtered := resources[:0]
	for _, summary := range resources {
		if summaryMatches(summary, search) {
			filtered = append(filtered, summary)
		}
	}
	return filtered, nil
}

func (s ResourceService) listResources(ctx context.Context, profile Profile, params *passboltapi.IndexResourcesParams, editor passboltapi.RequestEditorFn, folders map[string]FolderSummary, opts ...Option) ([]ResourceSummary, error) {
	client, err := s.Auth.AuthenticatedClient(ctx, profile, opts...)
	if err != nil {
		return nil, err
	}
	privateKey, err := s.Auth.unlockedPrivateKey(profile.Name)
	if err != nil {
		return nil, fmt.Errorf("unlock profile private key: %w", err)
	}
	defer privateKey.ClearPrivateParams()

	var editors []passboltapi.RequestEditorFn
	if editor != nil {
		editors = append(editors, editor)
	}
	resp, err := client.IndexResourcesWithResponse(ctx, params, editors...)
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, apiResponseError("list resources", resp.Status(), resp.Body)
	}

	summaries := make([]ResourceSummary, 0, len(resp.JSON200.Body))
	for _, item := range resp.JSON200.Body {
		summary, err := s.resourceSummary(ctx, client, item, privateKey, profile.UserID)
		if err != nil {
			return nil, err
		}
		summary.FolderPath = folderBreadcrumb(summary.FolderParentID, folders)
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func (s ResourceService) resourceSummary(ctx context.Context, client *Client, item passboltapi.ResourcesIndex_Body_Item, privateKey *crypto.Key, userID string) (ResourceSummary, error) {
	raw, err := item.MarshalJSON()
	if err != nil {
		return ResourceSummary{}, fmt.Errorf("read index resource: %w", err)
	}
	env, err := parseResourceEnvelope(raw)
	if err != nil {
		return ResourceSummary{}, fmt.Errorf("parse index resource: %w", err)
	}
	if env.IsV5 {
		v5, err := item.AsResourceV5IndexAndView()
		if err != nil {
			return ResourceSummary{}, fmt.Errorf("decode v5 index resource: %w", err)
		}
		metadata := map[string]any{}
		if strings.TrimSpace(v5.Metadata) != "" && privateKey != nil {
			env, err = metadataKeyParams(raw, v5)
			if err != nil {
				return ResourceSummary{}, err
			}
			plainMetadata, err := s.decryptV5Payload(ctx, client, v5.Metadata, env, privateKey, userID)
			if err == nil {
				_ = json.Unmarshal(plainMetadata, &metadata)
			} else if s.Debug != nil {
				fmt.Fprintf(s.Debug, "list summary: could not decrypt metadata for %s: %v\n", v5.Id, err)
			}
		}
		summary := summaryFromMetadata(v5.Id.String(), "v5", resourceTypeSlug(v5.ResourceType), metadata)
		summary.FolderParentID = nullableUUIDString(v5.FolderParentId.String())
		return summary, nil
	}
	v4, err := item.AsResourceV4IndexAndView()
	if err != nil {
		return ResourceSummary{}, fmt.Errorf("decode v4 index resource: %w", err)
	}
	metadata := map[string]any{
		"name":        v4.Name,
		"username":    v4.Username,
		"uri":         v4.Uri,
		"description": v4.Description,
	}
	summary := summaryFromMetadata(v4.Id.String(), "v4", resourceTypeSlug(v4.ResourceType), metadata)
	summary.FolderParentID = nullableUUIDString(v4.FolderParentId.String())
	return summary, nil
}

func summaryFromMetadata(id, kind, resourceType string, metadata map[string]any) ResourceSummary {
	uris := ResourceURIs(metadata, nil)
	uri := ""
	if len(uris) > 0 {
		uri = uris[0]
	}
	return ResourceSummary{
		ID:           id,
		Type:         kind,
		ResourceType: resourceType,
		Name:         metadataName(metadata),
		Username:     findMetadataString(metadata, "username"),
		URI:          uri,
		URIs:         uris,
		URL:          uri,
		Description:  findMetadataString(metadata, "description"),
	}
}

func summaryMatches(summary ResourceSummary, search string) bool {
	values := []string{summary.ID, summary.Type, summary.ResourceType, summary.Name, summary.Username, summary.URI, summary.URL, summary.Description, summary.FolderPath}
	values = append(values, summary.URIs...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), search) {
			return true
		}
	}
	return false
}

func (s ResourceService) listFolderSummaries(ctx context.Context, client *Client, privateKey *crypto.Key, userID string) (map[string]FolderSummary, error) {
	resp, err := client.IndexFoldersWithResponse(ctx, &passboltapi.IndexFoldersParams{})
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, apiResponseError("list folders", resp.Status(), resp.Body)
	}

	folders := make(map[string]FolderSummary, len(resp.JSON200.Body))
	for _, item := range resp.JSON200.Body {
		raw, err := item.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("read index folder: %w", err)
		}
		env, err := parseResourceEnvelope(raw)
		if err != nil {
			return nil, fmt.Errorf("parse index folder: %w", err)
		}
		if env.IsV5 {
			folder, err := item.AsFolderV5IndexAndView()
			if err != nil {
				return nil, fmt.Errorf("decode v5 index folder: %w", err)
			}
			metadata := map[string]any{}
			if strings.TrimSpace(folder.Metadata) != "" {
				env.RawMetadataKeyType = string(folder.MetadataKeyType)
				env.MetadataKeyType = normalizeMetadataKeyType(env.RawMetadataKeyType, folder.MetadataKeyId.String())
				env.MetadataKeyID = folder.MetadataKeyId.String()
				plain, decryptErr := s.decryptV5Payload(ctx, client, folder.Metadata, env, privateKey, userID)
				if decryptErr == nil {
					_ = json.Unmarshal(plain, &metadata)
				} else if s.Debug != nil {
					fmt.Fprintf(s.Debug, "folder summary: could not decrypt metadata for %s: %v\n", folder.Id, decryptErr)
				}
			}
			id := folder.Id.String()
			folders[id] = FolderSummary{
				ID:       id,
				ParentID: nullableUUIDString(folder.FolderParentId.String()),
				Name:     metadataName(metadata),
			}
			continue
		}

		folder, err := item.AsFolderV4IndexAndView()
		if err != nil {
			return nil, fmt.Errorf("decode v4 index folder: %w", err)
		}
		id := folder.Id.String()
		folders[id] = FolderSummary{
			ID:       id,
			ParentID: nullableUUIDString(folder.FolderParentId.String()),
			Name:     strings.TrimSpace(folder.Name),
		}
	}
	return folders, nil
}

func folderSummaryMap(folders []FolderSummary) map[string]FolderSummary {
	result := make(map[string]FolderSummary, len(folders))
	for _, folder := range folders {
		result[folder.ID] = folder
	}
	return result
}

func folderBreadcrumb(parentID string, folders map[string]FolderSummary) string {
	parentID = nullableUUIDString(parentID)
	if parentID == "" {
		return ""
	}

	var names []string
	seen := map[string]struct{}{}
	for parentID != "" {
		if _, exists := seen[parentID]; exists {
			break
		}
		seen[parentID] = struct{}{}
		folder, ok := folders[parentID]
		if !ok {
			break
		}
		name := strings.TrimSpace(folder.Name)
		if name == "" {
			name = folder.ID[:min(8, len(folder.ID))]
		}
		names = append(names, name)
		parentID = nullableUUIDString(folder.ParentID)
	}
	for left, right := 0, len(names)-1; left < right; left, right = left+1, right-1 {
		names[left], names[right] = names[right], names[left]
	}
	return strings.Join(names, " / ")
}

func nullableUUIDString(value string) string {
	if isZeroUUID(value) {
		return ""
	}
	return value
}

func viewResourceParams() *passboltapi.ViewResourceParams {
	containType := passboltapi.ViewResourceParamsContainResourceTypeN1
	containSecret := passboltapi.ViewResourceParamsContainSecretN1
	return &passboltapi.ViewResourceParams{
		ContainResourceType: &containType,
		ContainSecret:       &containSecret,
	}
}

func indexResourcesParams() *passboltapi.IndexResourcesParams {
	containType := passboltapi.IndexResourcesParamsContainResourceTypeN1
	return &passboltapi.IndexResourcesParams{
		ContainResourceType: &containType,
	}
}

func (s ResourceService) getByID(ctx context.Context, client *Client, id openapi_types.UUID, privateKey *crypto.Key, userID string) (DecryptedResource, error) {
	resp, err := client.ViewResourceWithResponse(ctx, id, viewResourceParams())
	if err != nil {
		return DecryptedResource{}, fmt.Errorf("view resource %s: %w", id, err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return DecryptedResource{}, fmt.Errorf("%w: %s", ErrResourceNotFound, id)
	}
	if resp.JSON200 == nil {
		return DecryptedResource{}, apiResponseError(fmt.Sprintf("view resource %s", id), resp.Status(), resp.Body)
	}
	resource, err := s.decryptViewBody(ctx, client, resp.JSON200.Body, privateKey, userID)
	if err != nil {
		return DecryptedResource{}, err
	}
	return s.finalizeResourceSecrets(ctx, client, id, privateKey, userID, resource)
}

func (s ResourceService) getByName(ctx context.Context, client *Client, name string, privateKey *crypto.Key, userID string) (DecryptedResource, error) {
	resp, err := client.IndexResourcesWithResponse(ctx, indexResourcesParams())
	if err != nil {
		return DecryptedResource{}, fmt.Errorf("list resources: %w", err)
	}
	if resp.JSON200 == nil {
		return DecryptedResource{}, apiResponseError("list resources", resp.Status(), resp.Body)
	}

	var matches, candidates, seen []string
	for _, item := range resp.JSON200.Body {
		id, decryptedName, err := s.resourceIDAndName(ctx, client, item, privateKey, userID)
		if err != nil {
			return DecryptedResource{}, err
		}
		candidates = append(candidates, id)
		if decryptedName != "" {
			seen = append(seen, fmt.Sprintf("%s (%s)", decryptedName, id))
		} else {
			seen = append(seen, fmt.Sprintf("<undecrypted name> (%s)", id))
		}
		if decryptedName == name {
			matches = append(matches, id)
		}
	}

	switch {
	case len(matches) == 1:
		return s.getByIDString(ctx, client, matches[0], privateKey, userID)
	case len(matches) > 1:
		return DecryptedResource{}, fmt.Errorf("%w: %q matches multiple resources (%s); reference the resource by its unique UUID", ErrResourceNameAmbiguous, name, strings.Join(matches, ", "))
	default:
		if s.Debug != nil {
			fmt.Fprintf(s.Debug, "search returned %d candidate(s): %s\n", len(candidates), strings.Join(seen, ", "))
		}
		return DecryptedResource{}, fmt.Errorf("%w: no resource exactly named %q; reference the resource by its unique UUID if the name cannot be decrypted or is ambiguous", ErrResourceNotFound, name)
	}
}

// resourceIDAndName resolves id and decrypted name from an index item. Secrets are not decrypted.
func (s ResourceService) resourceIDAndName(ctx context.Context, client *Client, item passboltapi.ResourcesIndex_Body_Item, privateKey *crypto.Key, userID string) (string, string, error) {
	raw, err := item.MarshalJSON()
	if err != nil {
		return "", "", fmt.Errorf("read index resource: %w", err)
	}
	env, err := parseResourceEnvelope(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse index resource: %w", err)
	}
	if env.IsV5 {
		v5, err := item.AsResourceV5IndexAndView()
		if err != nil {
			return "", "", fmt.Errorf("decode v5 index resource: %w", err)
		}
		if strings.TrimSpace(v5.Metadata) == "" {
			return v5.Id.String(), "", nil
		}
		env, err = metadataKeyParams(raw, v5)
		if err != nil {
			return "", "", err
		}
		plainMetadata, err := s.decryptV5Payload(ctx, client, v5.Metadata, env, privateKey, userID)
		if err != nil {
			if s.Debug != nil {
				fmt.Fprintf(s.Debug, "index name lookup: could not decrypt metadata for %s: %v\n", v5.Id, err)
			}
			return v5.Id.String(), "", nil
		}
		metadata := map[string]any{}
		if err := json.Unmarshal(plainMetadata, &metadata); err != nil {
			return v5.Id.String(), "", nil
		}
		return v5.Id.String(), metadataName(metadata), nil
	}
	v4, err := item.AsResourceV4IndexAndView()
	if err != nil {
		return "", "", fmt.Errorf("decode v4 index resource: %w", err)
	}
	return v4.Id.String(), strings.TrimSpace(v4.Name), nil
}

func (s ResourceService) getByIDString(ctx context.Context, client *Client, id string, privateKey *crypto.Key, userID string) (DecryptedResource, error) {
	parsed, err := parseUUID(id)
	if err != nil {
		return DecryptedResource{}, err
	}
	return s.getByID(ctx, client, parsed, privateKey, userID)
}

func (s ResourceService) decryptViewBody(ctx context.Context, client *Client, body passboltapi.ResourcesView_Body, privateKey *crypto.Key, userID string) (DecryptedResource, error) {
	raw, err := body.MarshalJSON()
	if err != nil {
		return DecryptedResource{}, fmt.Errorf("read resource view: %w", err)
	}
	env, err := parseResourceEnvelope(raw)
	if err != nil {
		return DecryptedResource{}, fmt.Errorf("parse resource view: %w", err)
	}
	if env.IsV5 {
		v5, secretsJSON, err := unmarshalV5Resource(raw)
		if err != nil {
			return DecryptedResource{}, fmt.Errorf("decode v5 resource: %w", err)
		}
		env, err = metadataKeyParams(raw, v5)
		if err != nil {
			return DecryptedResource{}, err
		}
		if s.Debug != nil {
			fmt.Fprintf(s.Debug, "resource %s metadata_key_type=%q metadata_key_id=%s\n", v5.Id, env.RawMetadataKeyType, env.MetadataKeyID)
		}
		return s.decryptV5(ctx, client, v5, secretsJSON, env, privateKey, userID)
	}
	v4, err := body.AsResourceV4IndexAndView()
	if err != nil {
		return DecryptedResource{}, fmt.Errorf("decode v4 resource: %w", err)
	}
	return s.decryptV4(v4, privateKey, userID)
}

func (s ResourceService) decryptV4(resource passboltapi.ResourceV4IndexAndView, privateKey *crypto.Key, userID string) (DecryptedResource, error) {
	metadata := map[string]any{
		"name":        resource.Name,
		"username":    resource.Username,
		"uri":         resource.Uri,
		"description": resource.Description,
	}
	var secrets []any
	if resource.Secrets != nil {
		var err error
		secrets, err = s.decryptSecretIndices(*resource.Secrets, privateKey, userID, resource.Id.String())
		if err != nil {
			return DecryptedResource{}, err
		}
	}
	return newDecryptedResource(resource.Id.String(), "v4", resourceTypeSlug(resource.ResourceType), metadata, secrets, resource, resource.Name), nil
}

func (s ResourceService) decryptV5(ctx context.Context, client *Client, resource passboltapi.ResourceV5IndexAndView, secretsJSON json.RawMessage, env resourceEnvelope, privateKey *crypto.Key, userID string) (DecryptedResource, error) {
	resourceID := resource.Id.String()
	metadata := map[string]any{}
	if strings.TrimSpace(resource.Metadata) != "" {
		plainMetadata, err := s.decryptV5Payload(ctx, client, resource.Metadata, env, privateKey, userID)
		if err != nil {
			return DecryptedResource{}, fmt.Errorf("resource %s: %w", resourceID, err)
		}
		if err := json.Unmarshal(plainMetadata, &metadata); err != nil {
			metadata["value"] = string(plainMetadata)
		}
	}
	secrets, err := s.decryptSecretsJSON(secretsJSON, privateKey, userID, resourceID)
	if err != nil {
		return DecryptedResource{}, err
	}
	return newDecryptedResource(resourceID, "v5", resourceTypeSlug(resource.ResourceType), metadata, secrets, resource, metadataName(metadata)), nil
}

func newDecryptedResource(id, kind, resourceType string, metadata map[string]any, secrets []any, raw any, name string) DecryptedResource {
	return DecryptedResource{
		ID:            id,
		Type:          kind,
		ResourceType:  resourceType,
		Metadata:      metadata,
		Secrets:       secrets,
		RawResource:   raw,
		DecryptedName: name,
	}
}

func (s ResourceService) decryptV5Payload(ctx context.Context, client *Client, armored string, env resourceEnvelope, privateKey *crypto.Key, userID string) ([]byte, error) {
	plain, err := s.decryptV5PayloadWithKeyType(ctx, client, armored, env.MetadataKeyType, env.MetadataKeyID, privateKey, userID)
	if err == nil {
		return plain, nil
	}
	if env.RawMetadataKeyType != "" {
		return nil, fmt.Errorf("decrypt metadata using %s: %w", env.MetadataKeyType, err)
	}
	alternate := alternateMetadataKeyType(env.MetadataKeyType)
	if alternate == "" {
		return nil, fmt.Errorf("decrypt metadata using %s: %w", env.MetadataKeyType, err)
	}
	plain, altErr := s.decryptV5PayloadWithKeyType(ctx, client, armored, alternate, env.MetadataKeyID, privateKey, userID)
	if altErr == nil {
		if s.Debug != nil {
			fmt.Fprintf(s.Debug, "decrypted metadata using %q after inferred %q failed\n", alternate, env.MetadataKeyType)
		}
		return plain, nil
	}
	return nil, fmt.Errorf("decrypt metadata (tried %q and %q): %w", env.MetadataKeyType, alternate, err)
}

func (s ResourceService) decryptV5PayloadWithKeyType(ctx context.Context, client *Client, armored, keyType, keyID string, privateKey *crypto.Key, userID string) ([]byte, error) {
	switch keyType {
	case "user_key":
		return s.PGP.DecryptArmored(armored, privateKey)
	case "shared_key":
		return s.decryptWithSharedMetadataKey(ctx, client, armored, keyID, privateKey, userID)
	default:
		return nil, fmt.Errorf("unsupported metadata key type %q", keyType)
	}
}

func (s ResourceService) decryptWithSharedMetadataKey(ctx context.Context, client *Client, armored, keyID string, privateKey *crypto.Key, userID string) ([]byte, error) {
	metadataKey, err := s.metadataPrivateKey(ctx, client, keyID, privateKey, userID)
	if err != nil {
		return nil, err
	}
	if key, unlockErr := s.PGP.UnlockPrivateKey(metadataKey, ""); unlockErr == nil {
		defer key.ClearPrivateParams()
		plain, decryptErr := s.PGP.DecryptArmored(armored, key)
		if decryptErr != nil {
			return nil, fmt.Errorf("decrypt with shared metadata private key %s: %w", keyID, decryptErr)
		}
		return plain, nil
	}
	plain, err := s.PGP.DecryptArmoredWithPassword(armored, metadataKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt with shared metadata key %s: %w", keyID, err)
	}
	return plain, nil
}

func alternateMetadataKeyType(keyType string) string {
	switch keyType {
	case "user_key":
		return "shared_key"
	case "shared_key":
		return "user_key"
	default:
		return ""
	}
}

func (s ResourceService) metadataPrivateKey(ctx context.Context, client *Client, keyID string, privateKey *crypto.Key, userID string) (string, error) {
	contain := passboltapi.IndexMetadataKeysParamsContainMetadataPrivateKeysN1
	resp, err := client.IndexMetadataKeysWithResponse(ctx, &passboltapi.IndexMetadataKeysParams{
		ContainMetadataPrivateKeys: &contain,
	})
	if err != nil {
		return "", fmt.Errorf("list metadata keys: %w", err)
	}
	if resp.JSON200 == nil {
		return "", apiResponseError("list metadata keys", resp.Status(), resp.Body)
	}
	for _, key := range resp.JSON200.Body {
		if key.Id.String() != keyID || key.MetadataPrivateKeys == nil {
			continue
		}
		var lastUnlockErr error
		for _, entry := range matchingMetadataPrivateKeys(*key.MetadataPrivateKeys, userID) {
			plain, err := s.PGP.DecryptArmored(entry.Data, privateKey)
			if err == nil {
				return strings.TrimSpace(string(plain)), nil
			}
			lastUnlockErr = err
		}
		if lastUnlockErr != nil {
			return "", fmt.Errorf("metadata key %s has private key copies, but none could be unlocked for user %s: %w", keyID, userID, lastUnlockErr)
		}
		return "", fmt.Errorf("metadata key %s has no private key copy for user %s", keyID, userID)
	}
	return "", fmt.Errorf("metadata key %s not found", keyID)
}

func (s ResourceService) finalizeResourceSecrets(ctx context.Context, client *Client, resourceID openapi_types.UUID, privateKey *crypto.Key, userID string, resource DecryptedResource) (DecryptedResource, error) {
	resource.Secrets = supplementSecretsFromMetadata(resource.Metadata, resource.Secrets)
	if hasUsableSecrets(resource.Secrets) {
		return resource, nil
	}

	var fallbackErr error
	if plain, err := s.viewSecretPayload(ctx, client, resourceID, privateKey); err == nil {
		if s.Debug != nil {
			fmt.Fprintf(s.Debug, "decrypted secret for resource %s via secrets endpoint\n", resource.ID)
		}
		resource.Secrets = []any{parseJSONOrString(plain)}
		return resource, nil
	} else {
		fallbackErr = err
		if s.Debug != nil {
			fmt.Fprintf(s.Debug, "secrets endpoint fallback failed for resource %s: %v\n", resource.ID, err)
		}
	}

	msg := fmt.Sprintf("resource %s: could not decrypt a secret with the profile private key", resource.ID)
	if userID = strings.TrimSpace(userID); userID != "" {
		msg += fmt.Sprintf(" (user_id %s)", userID)
	}
	msg += "; re-import your account kit if this resource opens in the Passbolt app but not here"
	return DecryptedResource{}, fmt.Errorf("%s: %w", msg, fallbackErr)
}

func (s ResourceService) viewSecretPayload(ctx context.Context, client *Client, resourceID openapi_types.UUID, privateKey *crypto.Key) ([]byte, error) {
	resp, err := client.ViewSecretWithResponse(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("view secret for resource %s: %w", resourceID, err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, fmt.Errorf("secret for resource %s not found", resourceID)
	}
	if resp.JSON200 == nil {
		return nil, apiResponseError(fmt.Sprintf("view secret for resource %s", resourceID), resp.Status(), resp.Body)
	}
	return s.PGP.DecryptArmored(resp.JSON200.Body.Data, privateKey)
}

func supplementSecretsFromMetadata(metadata map[string]any, secrets []any) []any {
	if hasUsableSecrets(secrets) || metadata == nil {
		return secrets
	}
	if payload := secretPayloadFromMetadata(metadata); len(payload) > 0 {
		return []any{payload}
	}
	return secrets
}

func secretPayloadFromMetadata(metadata map[string]any) map[string]any {
	payload := map[string]any{}
	for _, key := range []string{"password", "description"} {
		if value := findMetadataString(metadata, key); value != "" {
			payload[key] = value
		}
	}
	if value, ok := findMetadataValue(metadata, "totp"); ok {
		payload["totp"] = value
	}
	if len(payload) > 0 {
		return payload
	}
	if findMetadataString(metadata, "object_type") == "PASSBOLT_SECRET_DATA" {
		return copyStringFields(metadata, []string{"password", "description", "totp", "uri", "username"})
	}
	return nil
}

func findMetadataValue(metadata map[string]any, key string) (any, bool) {
	if value, exists := metadata[key]; exists {
		return value, true
	}
	for _, child := range metadata {
		switch typed := child.(type) {
		case map[string]any:
			if value, ok := findMetadataValue(typed, key); ok {
				return value, true
			}
		case []any:
			for _, item := range typed {
				if object, ok := item.(map[string]any); ok {
					if value, ok := findMetadataValue(object, key); ok {
						return value, true
					}
				}
			}
		}
	}
	return nil, false
}

func findMetadataString(metadata map[string]any, key string) string {
	if value := stringMapValue(metadata, key); value != "" {
		return value
	}
	for _, child := range metadata {
		switch typed := child.(type) {
		case map[string]any:
			if value := findMetadataString(typed, key); value != "" {
				return value
			}
		case []any:
			for _, item := range typed {
				if object, ok := item.(map[string]any); ok {
					if value := findMetadataString(object, key); value != "" {
						return value
					}
				}
			}
		}
	}
	return ""
}

// ResourceURIs returns the primary URI followed by any additional URIs.
// Passbolt v5 stores these in metadata.uris, while older resource types may
// expose a scalar uri or url.
func ResourceURIs(metadata map[string]any, secrets []any) []string {
	var uris []string
	seen := map[string]struct{}{}
	appendURI := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		uris = append(uris, value)
	}

	collect := func(values map[string]any) {
		for _, key := range []string{"uris", "uri", "url"} {
			raw, exists := values[key]
			if !exists {
				continue
			}
			switch uriValue := raw.(type) {
			case string:
				appendURI(uriValue)
			case []string:
				for _, uri := range uriValue {
					appendURI(uri)
				}
			case []any:
				for _, uri := range uriValue {
					if text, ok := uri.(string); ok {
						appendURI(text)
					}
				}
			}
		}
	}

	collect(metadata)
	if resource, ok := metadata["resource"].(map[string]any); ok {
		collect(resource)
	}
	for _, secret := range secrets {
		if values, ok := secret.(map[string]any); ok {
			collect(values)
			if resource, ok := values["resource"].(map[string]any); ok {
				collect(resource)
			}
		}
	}
	return uris
}

func copyStringFields(metadata map[string]any, keys []string) map[string]any {
	payload := map[string]any{}
	for _, key := range keys {
		if value := findMetadataString(metadata, key); value != "" {
			payload[key] = value
		}
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func hasUsableSecrets(secrets []any) bool {
	for _, secret := range secrets {
		if placeholder, ok := secret.(map[string]any); ok {
			if encrypted, _ := placeholder["encrypted"].(bool); encrypted {
				continue
			}
		}
		return true
	}
	return false
}

func parseJSONOrString(data []byte) any {
	var value any
	if err := json.Unmarshal(data, &value); err == nil {
		return value
	}
	return string(data)
}

func isArmoredPGPMessage(value string) bool {
	return strings.Contains(value, "-----BEGIN PGP MESSAGE-----")
}

func matchingV4Secrets(secrets []passboltapi.SecretIndex, userID string) []passboltapi.SecretIndex {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return secrets
	}
	var matches []passboltapi.SecretIndex
	for _, secret := range secrets {
		if strings.EqualFold(secret.UserId.String(), userID) {
			matches = append(matches, secret)
		}
	}
	if len(matches) == 0 && len(secrets) == 1 {
		return secrets
	}
	return matches
}

func unmarshalV5Resource(raw []byte) (passboltapi.ResourceV5IndexAndView, json.RawMessage, error) {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return passboltapi.ResourceV5IndexAndView{}, nil, err
	}
	secretsJSON := fields["secrets"]
	delete(fields, "secrets")
	withoutSecrets, err := json.Marshal(fields)
	if err != nil {
		return passboltapi.ResourceV5IndexAndView{}, nil, err
	}
	var resource passboltapi.ResourceV5IndexAndView
	if err := json.Unmarshal(withoutSecrets, &resource); err != nil {
		return passboltapi.ResourceV5IndexAndView{}, nil, err
	}
	return resource, secretsJSON, nil
}

func (s ResourceService) decryptSecretsJSON(secretsJSON json.RawMessage, privateKey *crypto.Key, userID, resourceID string) ([]any, error) {
	trimmed := strings.TrimSpace(string(secretsJSON))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var armored []string
	if err := json.Unmarshal(secretsJSON, &armored); err == nil {
		return s.decryptArmoredSecrets(armored, privateKey, resourceID)
	}
	var indices []passboltapi.SecretIndex
	if err := json.Unmarshal(secretsJSON, &indices); err == nil {
		return s.decryptSecretIndices(indices, privateKey, userID, resourceID)
	}
	return nil, fmt.Errorf("resource %s: unsupported secrets format in API response", resourceID)
}

func (s ResourceService) decryptArmoredSecrets(armored []string, privateKey *crypto.Key, resourceID string) ([]any, error) {
	encrypted, err := s.tryDecryptSecrets(armored, privateKey, func(i int) string {
		return fmt.Sprintf("resource %s secret #%d", resourceID, i+1)
	})
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (s ResourceService) decryptSecretIndices(indices []passboltapi.SecretIndex, privateKey *crypto.Key, userID, resourceID string) ([]any, error) {
	order := orderedSecretIndices(indices, userID)
	if len(order) == 0 && s.Debug != nil {
		fmt.Fprintf(s.Debug, "resource %s: no secret copies in the view response\n", resourceID)
	}
	payloads := make([]string, len(order))
	labels := make([]string, len(order))
	for i, secret := range order {
		payloads[i] = secret.Data
		labels[i] = fmt.Sprintf("resource %s secret for user %s", resourceID, secret.UserId)
	}
	encrypted, err := s.tryDecryptSecrets(payloads, privateKey, func(i int) string { return labels[i] })
	if err != nil {
		return nil, err
	}
	if len(order) > 0 && !hasUsableSecrets(encrypted) {
		for i, secret := range order {
			encrypted[i] = map[string]any{
				"encrypted": true,
				"user_id":   secret.UserId.String(),
				"data":      secret.Data,
			}
		}
	}
	return encrypted, nil
}

func (s ResourceService) tryDecryptSecrets(payloads []string, privateKey *crypto.Key, label func(int) string) ([]any, error) {
	var encrypted []any
	for i, payload := range payloads {
		decrypted, ok, err := s.decryptSecretPayload(payload, privateKey)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label(i), err)
		}
		if ok {
			return decrypted, nil
		}
		if s.Debug != nil {
			fmt.Fprintf(s.Debug, "%s is not decryptable with the profile private key\n", label(i))
		}
		encrypted = append(encrypted, map[string]any{
			"encrypted": true,
			"data":      payload,
		})
	}
	return encrypted, nil
}

func (s ResourceService) decryptSecretPayload(payload string, privateKey *crypto.Key) ([]any, bool, error) {
	if !isArmoredPGPMessage(payload) {
		return []any{parseJSONOrString([]byte(payload))}, true, nil
	}
	plain, err := s.PGP.DecryptArmored(payload, privateKey)
	if err != nil {
		if errors.Is(err, ErrSecretNotDecryptable) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return []any{parseJSONOrString(plain)}, true, nil
}

func orderedSecretIndices(indices []passboltapi.SecretIndex, userID string) []passboltapi.SecretIndex {
	preferred := matchingV4Secrets(indices, userID)
	seen := make(map[string]struct{}, len(indices))
	order := make([]passboltapi.SecretIndex, 0, len(indices))
	for _, secret := range preferred {
		order = append(order, secret)
		seen[secret.Id.String()] = struct{}{}
	}
	for _, secret := range indices {
		if _, ok := seen[secret.Id.String()]; ok {
			continue
		}
		order = append(order, secret)
	}
	return order
}

func normalizeMetadataKeyType(keyType, keyID string) string {
	keyType = strings.TrimSpace(keyType)
	switch keyType {
	case "user_key", "shared_key":
		return keyType
	}
	if strings.TrimSpace(keyID) != "" && !isZeroUUID(keyID) {
		return "shared_key"
	}
	return "user_key"
}

func isZeroUUID(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.EqualFold(value, "00000000-0000-0000-0000-000000000000")
}

func matchingMetadataPrivateKeys(keys []passboltapi.MetadataPrivateKeysIndexAndView, userID string) []passboltapi.MetadataPrivateKeysIndexAndView {
	userID = strings.TrimSpace(userID)
	if userID != "" {
		var matches []passboltapi.MetadataPrivateKeysIndexAndView
		for _, key := range keys {
			if strings.EqualFold(interfaceString(key.UserId), userID) {
				matches = append(matches, key)
			}
		}
		if len(matches) > 0 {
			return matches
		}
	}
	if len(keys) > 0 {
		return keys[:1]
	}
	return nil
}

func interfaceString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func stringMapValue(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func metadataName(metadata map[string]any) string {
	for _, key := range []string{"name", "title", "resource_name"} {
		if value := stringMapValue(metadata, key); value != "" {
			return value
		}
	}
	if resource, ok := metadata["resource"].(map[string]any); ok {
		if value := metadataName(resource); value != "" {
			return value
		}
	}
	if object, ok := metadata["object"].(map[string]any); ok {
		if value := metadataName(object); value != "" {
			return value
		}
	}
	return ""
}
