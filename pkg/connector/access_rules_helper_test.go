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

// TestSatisfiesRequireExclude_GroupRuleIsNotEnforced documents the accepted
// limitation: a "group" rule in Require or Exclude is never evaluated, so
// neither gates a user who otherwise matches. See the package doc comment
// in access_rules_helper.go and the "Access group rules" section of
// docs/connector.mdx.
func TestSatisfiesRequireExclude_GroupRuleIsNotEnforced(t *testing.T) {
	requireGroup := &cloudflare.AccessGroup{ID: "g1", Require: []interface{}{groupRule("eng")}}
	require.False(t, satisfiesRequireExclude(requireGroup, user("a@x.com")), "an unenforceable require rule fails closed: nobody satisfies it")

	excludeGroup := &cloudflare.AccessGroup{ID: "g2", Exclude: []interface{}{groupRule("banned")}}
	require.True(t, satisfiesRequireExclude(excludeGroup, user("a@x.com")), "an unenforceable exclude rule is not applied: it never blocks a match")
}

func TestContainsUnsupportedGroupRule(t *testing.T) {
	require.True(t, containsUnsupportedGroupRule([]interface{}{emailRule("a@x.com"), groupRule("eng")}))
	require.False(t, containsUnsupportedGroupRule([]interface{}{emailRule("a@x.com"), everyoneRule()}))
	require.False(t, containsUnsupportedGroupRule(nil))
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
