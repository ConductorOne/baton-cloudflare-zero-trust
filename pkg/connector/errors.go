package connector

import "fmt"

func wrapError(err error, message string) error {
	return fmt.Errorf("baton-cloudflare-zero-trust: %s: %w", message, err)
}
