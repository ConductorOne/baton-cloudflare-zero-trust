package connector

import (
	"testing"

	"github.com/cloudflare/cloudflare-go"
	"github.com/stretchr/testify/require"
)

func emailRule(email string) map[string]interface{} {
	return map[string]interface{}{"email": map[string]interface{}{"email": email}}
}

func emailDomainRule(domain string) map[string]interface{} {
	return map[string]interface{}{"email_domain": map[string]interface{}{"domain": domain}}
}

func everyoneRule() map[string]interface{} {
	return map[string]interface{}{"everyone": map[string]interface{}{}}
}

func geoRule(countryCode string) map[string]interface{} {
	return map[string]interface{}{"geo": map[string]interface{}{"country_code": countryCode}}
}

func groupRule(id string) map[string]interface{} {
	return map[string]interface{}{"group": map[string]interface{}{"id": id}}
}

func user(email string) cloudflare.AccessUser {
	return cloudflare.AccessUser{Email: email}
}

func TestRuleMatchesUser(t *testing.T) {
	require.True(t, ruleMatchesUser(emailRule("a@x.com"), user("a@x.com")))
	require.False(t, ruleMatchesUser(emailRule("a@x.com"), user("b@x.com")))
	require.True(t, ruleMatchesUser(emailDomainRule("x.com"), user("a@x.com")))
	require.False(t, ruleMatchesUser(emailDomainRule("x.com"), user("a@y.com")))
	require.True(t, ruleMatchesUser(everyoneRule(), user("anyone@x.com")))

	// "group" rules are only evaluated for Include (as an expandable grant
	// in groups.go, never through this function); ruleMatchesUser itself
	// never matches one, which is what makes Require/Exclude "group" rules
	// a documented no-op rather than a real membership check.
	require.False(t, ruleMatchesUser(groupRule("eng"), user("a@x.com")))
}

func TestSplitIncludeRules(t *testing.T) {
	direct, nestedGroupIDs := splitIncludeRules([]interface{}{
		emailRule("a@x.com"),
		groupRule("engineering"),
		everyoneRule(),
		groupRule("engineering"), // duplicate reference should be deduped
		groupRule("sales"),
	})

	require.Len(t, direct, 2, "email and everyone rules are direct, group rules are not")
	require.Equal(t, []string{"engineering", "sales"}, nestedGroupIDs)
}

func TestSatisfiesRequireExclude_NoRules(t *testing.T) {
	grp := &cloudflare.AccessGroup{ID: "g1"}

	require.True(t, satisfiesRequireExclude(grp, user("a@x.com")), "a user with no require/exclude rules is satisfied by default")
}

func TestSatisfiesRequireExclude_RequireAndExclude(t *testing.T) {
	grp := &cloudflare.AccessGroup{
		ID:      "g1",
		Require: []interface{}{emailDomainRule("x.com")},
		Exclude: []interface{}{emailRule("blocked@x.com")},
	}

	require.True(t, satisfiesRequireExclude(grp, user("a@x.com")))
	require.False(t, satisfiesRequireExclude(grp, user("a@y.com")), "require rule not satisfied for a different domain")
	require.False(t, satisfiesRequireExclude(grp, user("blocked@x.com")), "excluded user is not satisfied even though require is met")
}

// TestSatisfiesRequireExclude_UnevaluableRulesAreSkipped documents the
// accepted limitation: a rule this connector cannot evaluate is skipped in
// both lists rather than counted as a miss, so it neither empties the group
// (Require) nor blocks a match (Exclude). See the package doc comment in
// access_rules_helper.go and the "Access group rules" section of
// docs/connector.mdx.
func TestSatisfiesRequireExclude_UnevaluableRulesAreSkipped(t *testing.T) {
	tests := []struct {
		name  string
		group *cloudflare.AccessGroup
		want  bool
		why   string
	}{
		{
			"contextual require does not narrow membership",
			&cloudflare.AccessGroup{Require: []interface{}{geoRule("US")}},
			true,
			"a geo rule constrains the request, not who the policy grants access to",
		},
		{
			"nested group require is skipped",
			&cloudflare.AccessGroup{Require: []interface{}{groupRule("eng")}},
			true,
			"an unresolvable identity rule must not empty the group",
		},
		{
			"idp claim require is skipped",
			&cloudflare.AccessGroup{Require: []interface{}{map[string]interface{}{"okta": map[string]interface{}{"name": "eng"}}}},
			true,
			"",
		},
		{
			"evaluable require still gates",
			&cloudflare.AccessGroup{Require: []interface{}{emailRule("someone-else@x.com")}},
			false,
			"an email rule names identities and must be enforced",
		},
		{
			"evaluable require alongside a skipped one still gates",
			&cloudflare.AccessGroup{Require: []interface{}{geoRule("US"), emailRule("someone-else@x.com")}},
			false,
			"",
		},
		{
			"contextual exclude never blocks",
			&cloudflare.AccessGroup{Exclude: []interface{}{geoRule("US")}},
			true,
			"",
		},
		{
			"nested group exclude is not enforced",
			&cloudflare.AccessGroup{Exclude: []interface{}{groupRule("banned")}},
			true,
			"",
		},
		{
			"evaluable exclude still blocks",
			&cloudflare.AccessGroup{Exclude: []interface{}{emailRule("a@x.com")}},
			false,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, satisfiesRequireExclude(tt.group, user("a@x.com")), tt.why)
		})
	}
}

// TestAnyRuleMatches_UnevaluableRulesDoNotGrant checks the other neutral
// element: under Include's OR, a rule that cannot be evaluated must not
// admit the whole account.
func TestAnyRuleMatches_UnevaluableRulesDoNotGrant(t *testing.T) {
	require.False(t, anyRuleMatches([]interface{}{geoRule("US")}, user("a@x.com")))
	require.False(t, anyRuleMatches([]interface{}{groupRule("eng")}, user("a@x.com")))
	require.True(t, anyRuleMatches([]interface{}{geoRule("US"), emailRule("a@x.com")}, user("a@x.com")))
}

func TestUnresolvableIdentityRules(t *testing.T) {
	// Contextual rules are skipped by design and are not reported.
	require.Empty(t, unresolvableIdentityRules([]interface{}{emailRule("a@x.com"), everyoneRule(), geoRule("US")}))
	require.Empty(t, unresolvableIdentityRules(nil))

	require.Equal(t,
		[]string{"group:eng", "okta"},
		unresolvableIdentityRules([]interface{}{
			emailRule("a@x.com"),
			groupRule("eng"),
			map[string]interface{}{"okta": map[string]interface{}{"name": "eng"}},
		}),
	)
}

func TestDescribeAccessRule(t *testing.T) {
	tests := []struct {
		name string
		rule interface{}
		want string
	}{
		{"email", emailRule("a@x.com"), "email:a@x.com"},
		{"email_domain", emailDomainRule("x.com"), "email_domain:x.com"},
		{"everyone", everyoneRule(), "everyone"},
		{"group", groupRule("eng"), "group:eng"},
		{"ip", map[string]interface{}{"ip": map[string]interface{}{"ip": "10.0.0.0/8"}}, "ip:10.0.0.0/8"},
		{"ip_list", map[string]interface{}{"ip_list": map[string]interface{}{"id": "list1"}}, "ip_list:list1"},
		{"geo", map[string]interface{}{"geo": map[string]interface{}{"country_code": "US"}}, "geo:US"},
		{"certificate", map[string]interface{}{"certificate": map[string]interface{}{}}, "certificate"},
		{"unrecognized type still named", map[string]interface{}{"okta": map[string]interface{}{"name": "eng"}}, "okta"},
		{"not a map", "garbage", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, describeAccessRule(tt.rule))
		})
	}
}

func TestDescribeAccessRules(t *testing.T) {
	described := describeAccessRules([]interface{}{
		emailRule("a@x.com"),
		everyoneRule(),
		groupRule("eng"),
	})

	require.Equal(t, []interface{}{"email:a@x.com", "everyone", "group:eng"}, described)
}

func TestRestrictsNestedExpansion(t *testing.T) {
	tests := []struct {
		name  string
		group cloudflare.AccessGroup
		want  bool
	}{
		{
			name:  "no require or exclude",
			group: cloudflare.AccessGroup{Include: []interface{}{groupRule("eng")}},
			want:  false,
		},
		{
			name:  "require everyone only",
			group: cloudflare.AccessGroup{Require: []interface{}{everyoneRule()}},
			want:  false,
		},
		{
			name:  "require email narrows the set",
			group: cloudflare.AccessGroup{Require: []interface{}{emailRule("a@x.com")}},
			want:  true,
		},
		{
			name:  "require everyone alongside a narrowing rule",
			group: cloudflare.AccessGroup{Require: []interface{}{everyoneRule(), emailDomainRule("x.com")}},
			want:  true,
		},
		{
			// A skipped rule filters nothing, so it cannot filter the
			// expanded set either.
			name:  "require references a group",
			group: cloudflare.AccessGroup{Require: []interface{}{groupRule("eng")}},
			want:  false,
		},
		{
			name:  "contextual require does not restrict",
			group: cloudflare.AccessGroup{Require: []interface{}{geoRule("US")}},
			want:  false,
		},
		{
			name:  "contextual exclude does not restrict",
			group: cloudflare.AccessGroup{Exclude: []interface{}{geoRule("US")}},
			want:  false,
		},
		{
			name:  "an evaluable exclude restricts",
			group: cloudflare.AccessGroup{Exclude: []interface{}{emailRule("a@x.com")}},
			want:  true,
		},
		{
			name:  "exclude wins over a harmless require",
			group: cloudflare.AccessGroup{Require: []interface{}{everyoneRule()}, Exclude: []interface{}{everyoneRule()}},
			want:  true,
		},
		{
			name:  "malformed require rule is skipped, not restrictive",
			group: cloudflare.AccessGroup{Require: []interface{}{"garbage"}},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, restrictsNestedExpansion(&tt.group))
		})
	}
}
