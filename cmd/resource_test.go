package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/emqmalte/bolty/internal/passbolt"
)

func TestWriteResourceOutputIncludesRawResourceOnlyInDebug(t *testing.T) {
	t.Parallel()

	resource := passbolt.DecryptedResource{
		ID:          "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88",
		Type:        "v4",
		RawResource: map[string]any{"encrypted": "payload"},
	}

	var normal bytes.Buffer
	if err := writeResourceOutput(&normal, resource, false); err != nil {
		t.Fatal(err)
	}
	var normalJSON map[string]any
	if err := json.Unmarshal(normal.Bytes(), &normalJSON); err != nil {
		t.Fatal(err)
	}
	if _, ok := normalJSON["raw_resource"]; ok {
		t.Fatalf("raw_resource should not be in normal output: %s", normal.String())
	}

	var debug bytes.Buffer
	if err := writeResourceOutput(&debug, resource, true); err != nil {
		t.Fatal(err)
	}
	var debugJSON map[string]any
	if err := json.Unmarshal(debug.Bytes(), &debugJSON); err != nil {
		t.Fatal(err)
	}
	if _, ok := debugJSON["raw_resource"]; !ok {
		t.Fatalf("raw_resource should be in debug output: %s", debug.String())
	}
}
