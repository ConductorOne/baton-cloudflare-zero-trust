package connector

import (
	"context"
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

func TestGroupIncludesUser_Include(t *testing.T) {
	grp := &cloudflare.AccessGroup{
		ID:      "g1",
		Include: []interface{}{emailRule("a@x.com")},
	}

	matches, err := groupIncludesUser(context.Background(), nil, "acct", grp, user("a@x.com"), map[string]*cloudflare.AccessGroup{}, map[string]bool{})
	require.NoError(t, err)
	require.True(t, matches)

	matches, err = groupIncludesUser(context.Background(), nil, "acct", grp, user("b@x.com"), map[string]*cloudflare.AccessGroup{}, map[string]bool{})
	require.NoError(t, err)
	require.False(t, matches)
}

func TestGroupIncludesUser_Exclude(t *testing.T) {
	grp := &cloudflare.AccessGroup{
		ID:      "g1",
		Include: []interface{}{everyoneRule()},
		Exclude: []interface{}{emailRule("blocked@x.com")},
	}

	matches, err := groupIncludesUser(context.Background(), nil, "acct", grp, user("blocked@x.com"), map[string]*cloudflare.AccessGroup{}, map[string]bool{})
	require.NoError(t, err)
	require.False(t, matches, "excluded user must not be granted even though everyone is included")

	matches, err = groupIncludesUser(context.Background(), nil, "acct", grp, user("anyone@x.com"), map[string]*cloudflare.AccessGroup{}, map[string]bool{})
	require.NoError(t, err)
	require.True(t, matches)
}

func TestGroupIncludesUser_Require(t *testing.T) {
	grp := &cloudflare.AccessGroup{
		ID:      "g1",
		Include: []interface{}{everyoneRule()},
		Require: []interface{}{emailDomainRule("x.com")},
	}

	matches, err := groupIncludesUser(context.Background(), nil, "acct", grp, user("a@x.com"), map[string]*cloudflare.AccessGroup{}, map[string]bool{})
	require.NoError(t, err)
	require.True(t, matches)

	matches, err = groupIncludesUser(context.Background(), nil, "acct", grp, user("a@y.com"), map[string]*cloudflare.AccessGroup{}, map[string]bool{})
	require.NoError(t, err)
	require.False(t, matches, "require rule not satisfied for a different domain")
}

func TestGroupIncludesUser_NestedGroup(t *testing.T) {
	leaf := &cloudflare.AccessGroup{
		ID:      "leaf",
		Include: []interface{}{emailRule("nested@x.com")},
	}
	top := &cloudflare.AccessGroup{
		ID:      "top",
		Include: []interface{}{groupRule("leaf")},
	}
	groups := map[string]*cloudflare.AccessGroup{"leaf": leaf}

	matches, err := groupIncludesUser(context.Background(), nil, "acct", top, user("nested@x.com"), groups, map[string]bool{})
	require.NoError(t, err)
	require.True(t, matches)

	matches, err = groupIncludesUser(context.Background(), nil, "acct", top, user("other@x.com"), groups, map[string]bool{})
	require.NoError(t, err)
	require.False(t, matches)
}

func TestGroupIncludesUser_CycleGuard(t *testing.T) {
	groupA := &cloudflare.AccessGroup{ID: "a", Include: []interface{}{groupRule("b")}}
	groupB := &cloudflare.AccessGroup{ID: "b", Include: []interface{}{groupRule("a")}}
	groups := map[string]*cloudflare.AccessGroup{"a": groupA, "b": groupB}

	matches, err := groupIncludesUser(context.Background(), nil, "acct", groupA, user("a@x.com"), groups, map[string]bool{})
	require.NoError(t, err)
	require.False(t, matches, "a group cycle must not match and must not infinite loop")
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

	satisfied, err := satisfiesRequireExclude(context.Background(), nil, "acct", grp, user("a@x.com"), map[string]*cloudflare.AccessGroup{})
	require.NoError(t, err)
	require.True(t, satisfied, "a user with no require/exclude rules is satisfied by default")
}

func TestSatisfiesRequireExclude_RequireAndExclude(t *testing.T) {
	grp := &cloudflare.AccessGroup{
		ID:      "g1",
		Require: []interface{}{emailDomainRule("x.com")},
		Exclude: []interface{}{emailRule("blocked@x.com")},
	}

	satisfied, err := satisfiesRequireExclude(context.Background(), nil, "acct", grp, user("a@x.com"), map[string]*cloudflare.AccessGroup{})
	require.NoError(t, err)
	require.True(t, satisfied)

	satisfied, err = satisfiesRequireExclude(context.Background(), nil, "acct", grp, user("a@y.com"), map[string]*cloudflare.AccessGroup{})
	require.NoError(t, err)
	require.False(t, satisfied, "require rule not satisfied for a different domain")

	satisfied, err = satisfiesRequireExclude(context.Background(), nil, "acct", grp, user("blocked@x.com"), map[string]*cloudflare.AccessGroup{})
	require.NoError(t, err)
	require.False(t, satisfied, "excluded user is not satisfied even though require is met")
}

func TestSatisfiesRequireExclude_NestedGroupExclude(t *testing.T) {
	banned := &cloudflare.AccessGroup{ID: "banned", Include: []interface{}{emailRule("bad@x.com")}}
	grp := &cloudflare.AccessGroup{
		ID:      "g1",
		Exclude: []interface{}{groupRule("banned")},
	}
	groups := map[string]*cloudflare.AccessGroup{"banned": banned}

	satisfied, err := satisfiesRequireExclude(context.Background(), nil, "acct", grp, user("bad@x.com"), groups)
	require.NoError(t, err)
	require.False(t, satisfied, "a user excluded via nested group membership must not be satisfied")

	satisfied, err = satisfiesRequireExclude(context.Background(), nil, "acct", grp, user("ok@x.com"), groups)
	require.NoError(t, err)
	require.True(t, satisfied)
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
