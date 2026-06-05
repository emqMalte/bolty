package passbolt

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestWrapPGPErrorIncorrectKey(t *testing.T) {
	t.Parallel()

	err := wrapPGPError(fmt.Errorf("openpgp: incorrect key"))
	if !errors.Is(err, ErrSecretNotDecryptable) {
		t.Fatalf("expected ErrSecretNotDecryptable, got %v", err)
	}
}

func TestAPIBodyExcerptTruncatesLongBodies(t *testing.T) {
	t.Parallel()

	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	excerpt := apiBodyExcerpt(long)
	if len(excerpt) > 270 {
		t.Fatalf("expected truncated excerpt, got len %d", len(excerpt))
	}
	if !strings.HasSuffix(excerpt, "…)") {
		t.Fatalf("expected ellipsis suffix, got %q", excerpt)
	}
}
