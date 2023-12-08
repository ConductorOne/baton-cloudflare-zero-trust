package connector

import "fmt"

func wrapError(err error, message string) error {
	return fmt.Errorf("cloudflare-zero-trust-connector: %s: %w", message, err)
}
