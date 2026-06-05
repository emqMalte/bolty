package inject

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/emqmalte/bolty/internal/passbolt"
)

type ResourceResolver func(context.Context, string) (passbolt.DecryptedResource, error)

func Render(ctx context.Context, template string, resolve ResourceResolver) (string, error) {
	placeholders, err := parsePlaceholdersStrict(template)
	if err != nil {
		return "", err
	}
	if len(placeholders) == 0 {
		return template, nil
	}
	if resolve == nil {
		return "", fmt.Errorf("resource resolver is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	cache := map[string]passbolt.DecryptedResource{}
	var rendered strings.Builder
	rendered.Grow(len(template))
	last := 0

	for _, placeholder := range placeholders {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		ref, err := ParsePassboltRef(placeholder.Inner)
		if err != nil {
			return "", fmt.Errorf("placeholder %q: %w", placeholder.Raw, err)
		}

		resource, ok := cache[ref.Resource]
		if !ok {
			resource, err = resolve(ctx, ref.Resource)
			if err != nil {
				return "", resourceLookupError(placeholder, ref.Resource, err)
			}
			cache[ref.Resource] = resource
		}

		value, err := passboltRefValue(resource, ref)
		if err != nil {
			return "", fmt.Errorf("placeholder %q: %w", placeholder.Raw, err)
		}

		rendered.WriteString(template[last:placeholder.Start])
		rendered.WriteString(value)
		last = placeholder.End
	}

	rendered.WriteString(template[last:])
	return rendered.String(), nil
}

func resourceLookupError(placeholder placeholder, resourceRef string, err error) error {
	if errors.Is(err, passbolt.ErrResourceNotFound) {
		return fmt.Errorf("placeholder %q references missing resource %q: %w", placeholder.Raw, resourceRef, err)
	}
	return fmt.Errorf("placeholder %q: get Passbolt resource %q: %w", placeholder.Raw, resourceRef, err)
}
