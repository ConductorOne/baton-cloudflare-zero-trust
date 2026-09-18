package connector

import (
	"testing"

	"github.com/cloudflare/cloudflare-go"
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

// TestRevokeDecision drives the production decision function, so the ordering
// between the still-a-member check and the not-found case is pinned here
// rather than restated.
func TestRevokeDecision(t *testing.T) {
	const email = "jane@x.com"

	tests := []struct {
		name  string
		group cloudflare.AccessGroup
		want  revokeOutcome
	}{
		{
			name:  "own email rule is the only source of membership",
			group: cloudflare.AccessGroup{Include: []interface{}{emailRule(email), emailRule("other@x.com")}},
			want:  revokeRemoveRule,
		},
		{
			name:  "email rule alongside a domain rule that still admits them",
			group: cloudflare.AccessGroup{Include: []interface{}{emailRule(email), emailDomainRule("x.com")}},
			want:  revokeBlocked,
		},
		{
			name:  "email rule alongside an everyone rule",
			group: cloudflare.AccessGroup{Include: []interface{}{emailRule(email), everyoneRule()}},
			want:  revokeBlocked,
		},
		{
			name:  "membership comes only from a domain rule",
			group: cloudflare.AccessGroup{Include: []interface{}{emailDomainRule("x.com")}},
			want:  revokeBlocked,
		},
		{
			name:  "no rule admits them",
			group: cloudflare.AccessGroup{Include: []interface{}{emailRule("other@x.com"), emailDomainRule("y.com")}},
			want:  revokeNotAMember,
		},
		{
			name:  "a nested group rule is not evaluated, so it does not block the revoke",
			group: cloudflare.AccessGroup{Include: []interface{}{emailRule(email), groupRule("eng")}},
			want:  revokeRemoveRule,
		},
		{
			// Without applying Exclude, a broad Include rule would report
			// this user as still a member and send the operator after a rule
			// that is not granting them anything.
			name: "a broad Include rule the user is excluded from",
			group: cloudflare.AccessGroup{
				Include: []interface{}{emailDomainRule("x.com")},
				Exclude: []interface{}{emailRule(email)},
			},
			want: revokeNotAMember,
		},
		{
			name: "a broad Include rule the user fails Require for",
			group: cloudflare.AccessGroup{
				Include: []interface{}{everyoneRule()},
				Require: []interface{}{emailDomainRule("corp.com")},
			},
			want: revokeNotAMember,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := revokeDecision(&tt.group, email)
			require.Equal(t, tt.want, got)
		})
	}

	// Cloudflare rejects a group with an empty Include list, so Revoke guards
	// on the filtered list being empty. This pins the case that reaches it.
	t.Run("revoking the only member empties the include list", func(t *testing.T) {
		grp := cloudflare.AccessGroup{Include: []interface{}{emailRule(email)}}

		include, got := revokeDecision(&grp, email)

		require.Equal(t, revokeRemoveRule, got)
		require.Empty(t, include, "the guard in Revoke refuses rather than PUT an empty include")
	})
}

// TestHasEvaluableRule covers the guard behind the "this group reports no
// members" log: an Include list with nothing evaluable cannot be decided, and
// the empty result is a gap rather than an answer.
func TestHasEvaluableRule(t *testing.T) {
	require.True(t, hasEvaluableRule([]interface{}{geoRule("US"), emailRule("a@x.com")}))
	require.True(t, hasEvaluableRule([]interface{}{everyoneRule()}))
	require.False(t, hasEvaluableRule([]interface{}{geoRule("US"), groupRule("eng")}))
	require.False(t, hasEvaluableRule([]interface{}{map[string]interface{}{"okta": map[string]interface{}{"name": "eng"}}}))
	require.False(t, hasEvaluableRule(nil))
}
