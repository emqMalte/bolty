package cmd

import (
	"net/http"
	"testing"
)

func TestPassboltClientOptionsDoNotSkipTLSByDefault(t *testing.T) {
	t.Parallel()

	opts := passboltClientOptionsForTLS(false)
	if len(opts) != 0 {
		t.Fatalf("default client options should not override TLS behavior, got %d option(s)", len(opts))
	}
}

func TestPassboltClientOptionsSkipTLSOnlyWhenExplicit(t *testing.T) {
	t.Parallel()

	opts := passboltClientOptionsForTLS(true)
	if len(opts) != 1 {
		t.Fatalf("expected one explicit TLS override option, got %d", len(opts))
	}

	client := insecureSkipTLSHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected explicit client to enable InsecureSkipVerify, got %#v", transport.TLSClientConfig)
	}
}
