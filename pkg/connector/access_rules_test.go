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
	cache := map[string]*cloudflare.AccessGroup{"leaf": leaf}

	matches, err := groupIncludesUser(context.Background(), nil, "acct", top, user("nested@x.com"), cache, map[string]bool{})
	require.NoError(t, err)
	require.True(t, matches)

	matches, err = groupIncludesUser(context.Background(), nil, "acct", top, user("other@x.com"), cache, map[string]bool{})
	require.NoError(t, err)
	require.False(t, matches)
}

func TestGroupIncludesUser_CycleGuard(t *testing.T) {
	groupA := &cloudflare.AccessGroup{ID: "a", Include: []interface{}{groupRule("b")}}
	groupB := &cloudflare.AccessGroup{ID: "b", Include: []interface{}{groupRule("a")}}
	cache := map[string]*cloudflare.AccessGroup{"a": groupA, "b": groupB}

	matches, err := groupIncludesUser(context.Background(), nil, "acct", groupA, user("a@x.com"), cache, map[string]bool{})
	require.NoError(t, err)
	require.False(t, matches, "a group cycle must not match and must not infinite loop")
}
