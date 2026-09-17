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

// TestRevokeRebuildPreservesNonEmailRules covers the filtering Revoke applies
// to a group's Include list. A group's membership can come from email_domain,
// everyone or a nested group as well, and dropping those rules here would
// delete them from the group on the UpdateAccessGroup that follows.
func TestRevokeRebuildPreservesNonEmailRules(t *testing.T) {
	original := []interface{}{
		emailRule("keep@x.com"),
		everyoneRule(),
		emailRule("revoke@x.com"),
		groupRule("eng"),
		emailDomainRule("x.com"),
	}

	var rebuilt []interface{}
	found := false
	for _, rule := range original {
		if ruleEmail, ok := includeRuleEmail(rule); ok && ruleEmail == "revoke@x.com" {
			found = true
			continue
		}
		rebuilt = append(rebuilt, rule)
	}

	require.True(t, found)
	require.Equal(t, []interface{}{
		emailRule("keep@x.com"),
		everyoneRule(),
		groupRule("eng"),
		emailDomainRule("x.com"),
	}, rebuilt, "only the revoked email rule is removed; every other rule survives")
}
