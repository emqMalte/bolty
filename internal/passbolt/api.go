package passbolt

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	passboltapi "github.com/emqmalte/bolty/generated/passbolt"
)

const defaultTimeout = 30 * time.Second

// Client is the application-level Passbolt API client.
//
// It embeds the generated typed client, so callers can use generated methods
// directly, for example: client.IndexResourcesWithResponse(ctx, params).
type Client struct {
	*passboltapi.ClientWithResponses
}

type config struct {
	httpClient     passboltapi.HttpRequestDoer
	requestEditors []passboltapi.RequestEditorFn
}

// Option configures a Client.
type Option func(*config) error

// NewClient creates a typed Passbolt API client for baseURL.
func NewClient(baseURL string, opts ...Option) (*Client, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, errors.New("passbolt base URL is required")
	}

	cfg := config{
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	clientOpts := []passboltapi.ClientOption{
		passboltapi.WithHTTPClient(cfg.httpClient),
	}
	for _, editor := range cfg.requestEditors {
		clientOpts = append(clientOpts, passboltapi.WithRequestEditorFn(editor))
	}

	client, err := passboltapi.NewClientWithResponses(baseURL, clientOpts...)
	if err != nil {
		return nil, err
	}

	return &Client{ClientWithResponses: client}, nil
}

// WithHTTPClient uses a custom HTTP client or transport-backed doer.
func WithHTTPClient(httpClient passboltapi.HttpRequestDoer) Option {
	return func(cfg *config) error {
		if httpClient == nil {
			return errors.New("http client is required")
		}
		cfg.httpClient = httpClient
		return nil
	}
}

// WithBearerToken adds an Authorization header to every generated request.
func WithBearerToken(token string) Option {
	return func(cfg *config) error {
		token = strings.TrimSpace(token)
		if token == "" {
			return errors.New("bearer token is required")
		}
		cfg.requestEditors = append(cfg.requestEditors, func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		})
		return nil
	}
}

// WithCookie adds a cookie to every generated request.
func WithCookie(cookie *http.Cookie) Option {
	return func(cfg *config) error {
		if cookie == nil {
			return errors.New("cookie is required")
		}
		cfg.requestEditors = append(cfg.requestEditors, func(_ context.Context, req *http.Request) error {
			req.AddCookie(cookie)
			return nil
		})
		return nil
	}
}

// WithHeader adds a static header to every generated request.
func WithHeader(name, value string) Option {
	return func(cfg *config) error {
		name = strings.TrimSpace(name)
		if name == "" {
			return errors.New("header name is required")
		}
		cfg.requestEditors = append(cfg.requestEditors, func(_ context.Context, req *http.Request) error {
			req.Header.Set(name, value)
			return nil
		})
		return nil
	}
}

// WithRequestEditor adds a generated-client request editor.
func WithRequestEditor(editor passboltapi.RequestEditorFn) Option {
	return func(cfg *config) error {
		if editor == nil {
			return errors.New("request editor is required")
		}
		cfg.requestEditors = append(cfg.requestEditors, editor)
		return nil
	}
}
