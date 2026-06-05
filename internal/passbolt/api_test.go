package passbolt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientUsesGeneratedClientAndRequestEditors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthcheck.json" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.Header.Get("X-Test"); got != "value" {
			t.Fatalf("unexpected X-Test header: %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"header": map[string]any{
				"status": "success",
			},
			"body": map[string]any{},
		}); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(
		server.URL,
		WithBearerToken("token"),
		WithHeader("X-Test", "value"),
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.ViewHealthcheckWithResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode())
	}
	if resp.JSON200 == nil {
		t.Fatal("expected parsed JSON200 response")
	}
}
