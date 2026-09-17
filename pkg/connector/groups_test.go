package connector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIncludeRuleEmail(t *testing.T) {
	tests := []struct {
		name  string
		rule  interface{}
		want  string
		found bool
	}{
		{"email rule", emailRule("a@x.com"), "a@x.com", true},
		{"email_domain rule", emailDomainRule("x.com"), "", false},
		{"everyone rule", everyoneRule(), "", false},
		{"nested group rule", groupRule("eng"), "", false},
		{"geo rule", geoRule("US"), "", false},
		{"not a map", "garbage", "", false},
		{"email sub-map missing", map[string]interface{}{"email": "a@x.com"}, "", false},
		{"email value not a string", map[string]interface{}{"email": map[string]interface{}{"email": 42}}, "", false},
		{"email value empty", map[string]interface{}{"email": map[string]interface{}{"email": ""}}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := includeRuleEmail(tt.rule)
			require.Equal(t, tt.found, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestFilterIncludeEmail covers the filter Revoke applies to a group's
// Include list. It calls the production function rather than restating the
// loop, so a regression in Revoke's filtering is caught here.
func TestFilterIncludeEmail(t *testing.T) {
	original := []interface{}{
		emailRule("keep@x.com"),
		everyoneRule(),
		emailRule("revoke@x.com"),
		groupRule("eng"),
		emailDomainRule("x.com"),
	}

	t.Run("removes only the named address", func(t *testing.T) {
		rebuilt, found := filterIncludeEmail(original, "revoke@x.com")

		require.True(t, found)
		require.Equal(t, []interface{}{
			emailRule("keep@x.com"),
			everyoneRule(),
			groupRule("eng"),
			emailDomainRule("x.com"),
		}, rebuilt, "every rule other than the revoked email survives")
	})

	t.Run("matches the address case-insensitively", func(t *testing.T) {
		rebuilt, found := filterIncludeEmail(original, "REVOKE@X.COM")

		require.True(t, found, "Cloudflare addresses are compared case-insensitively")
		require.Len(t, rebuilt, 4)
	})

	t.Run("reports not found when no email rule names the address", func(t *testing.T) {
		rebuilt, found := filterIncludeEmail(original, "absent@x.com")

		require.False(t, found)
		require.Equal(t, original, rebuilt, "the list is unchanged when nothing matched")
	})

	t.Run("empty include list", func(t *testing.T) {
		rebuilt, found := filterIncludeEmail(nil, "a@x.com")

		require.False(t, found)
		require.Empty(t, rebuilt)
	})
}
