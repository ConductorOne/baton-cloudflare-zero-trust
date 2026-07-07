package connector

import (
	"strings"

	"github.com/cloudflare/cloudflare-go"
)

// This connector evaluates Cloudflare Access Group Include/Require/Exclude
// rules against account members to decide grants:
//   - Include is OR: at least one rule must match.
//   - Require is AND: every rule must match.
//   - Exclude is NOT: no rule may match.
//
// Supported rule types differ by list, and this is intentional, not an
// oversight:
//
//   - Include supports "email", "email_domain", "everyone", and "group"
//     (a nested Access Group). "group" is resolved as a GrantExpandable
//     grant in groups.go rather than evaluated here — see splitIncludeRules.
//
//   - Require and Exclude support only "email", "email_domain", and
//     "everyone". A "group" rule in Require or Exclude is NOT evaluated:
//     doing so would require recursively re-running this same Include/
//     Require/Exclude evaluation against the referenced group for every
//     member, which this connector deliberately does not do (see the
//     "Access group rules" section in docs/connector.mdx for the reasoning
//     and its consequences). A "group" rule in Require always fails to
//     match, so it never grants access through that path (safe: no grants
//     are fabricated). A "group" rule in Exclude is silently NOT enforced:
//     members who should be excluded via nested-group membership may still
//     receive a grant. containsUnsupportedGroupRule flags this case so
//     Grants() can log a warning.
//
// Any other rule type (ip, certificate, IdP-group claims, etc.) also never
// matches, since it doesn't identify a user by email and this connector's
// grants are keyed on user identity.
func ruleMatchesUser(rule interface{}, user cloudflare.AccessUser) bool {
	rm, ok := rule.(map[string]interface{})
	if !ok {
		return false
	}

	if _, ok := rm["everyone"]; ok {
		return true
	}

	if em, ok := rm["email"].(map[string]interface{}); ok {
		email, _ := em["email"].(string)
		return email != "" && strings.EqualFold(email, user.Email)
	}

	if ed, ok := rm["email_domain"].(map[string]interface{}); ok {
		domain, _ := ed["domain"].(string)
		return domain != "" && strings.EqualFold(emailDomain(user.Email), domain)
	}

	return false
}

func anyRuleMatches(rules []interface{}, user cloudflare.AccessUser) bool {
	for _, rule := range rules {
		if ruleMatchesUser(rule, user) {
			return true
		}
	}
	return false
}

// splitIncludeRules separates a group's Include rules into direct,
// user-identifying rules ("email", "email_domain", "everyone") and the IDs
// of any nested groups referenced via a "group" rule.
//
// Nested-group Include rules are intentionally NOT flattened into per-user
// grants here: the caller emits a single GrantExpandable grant per
// referenced group instead, so C1's graph expansion resolves that group's
// membership (including any further nesting) without the connector
// re-walking every account member on every sync.
func splitIncludeRules(rules []interface{}) ([]interface{}, []string) {
	var direct []interface{}
	var nestedGroupIDs []string
	seen := map[string]bool{}
	for _, rule := range rules {
		rm, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		if grpRule, ok := rm["group"].(map[string]interface{}); ok {
			id, _ := grpRule["id"].(string)
			if id != "" && !seen[id] {
				seen[id] = true
				nestedGroupIDs = append(nestedGroupIDs, id)
			}
			continue
		}
		direct = append(direct, rule)
	}
	return direct, nestedGroupIDs
}

// satisfiesRequireExclude checks a group's Require (AND) and Exclude (NOT)
// rules against a user that has already matched one of the group's direct
// Include rules. See the package doc comment above for why "group" rules
// here are not evaluated.
func satisfiesRequireExclude(grp *cloudflare.AccessGroup, user cloudflare.AccessUser) bool {
	for _, rule := range grp.Require {
		if !ruleMatchesUser(rule, user) {
			return false
		}
	}

	return !anyRuleMatches(grp.Exclude, user)
}

// containsUnsupportedGroupRule reports whether rules includes a "group"
// rule, used to warn when a group's Require/Exclude references a nested
// group that this connector won't evaluate (see the package doc comment).
func containsUnsupportedGroupRule(rules []interface{}) bool {
	for _, rule := range rules {
		rm, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		if _, ok := rm["group"].(map[string]interface{}); ok {
			return true
		}
	}
	return false
}

// describeAccessRules renders a group's Include/Require/Exclude rules as
// short human-readable strings for the group's resource profile, so
// customers can see how a group is configured without pulling the raw
// Cloudflare API response. Returned as []interface{} since that's the list
// type structpb.NewStruct accepts for a profile field.
func describeAccessRules(rules []interface{}) []interface{} {
	described := make([]interface{}, 0, len(rules))
	for _, rule := range rules {
		described = append(described, describeAccessRule(rule))
	}
	return described
}

// describeAccessRule renders a single rule as "type:value" (or just "type"
// when it has no value, e.g. "everyone"). Rule types this connector doesn't
// evaluate for membership (ip, certificate, IdP-group claims, etc.) are
// still named so operators can see the rule exists, even though it has no
// effect on the grants this connector emits.
func describeAccessRule(rule interface{}) string {
	rm, ok := rule.(map[string]interface{})
	if !ok || len(rm) == 0 {
		return "unknown"
	}

	switch {
	case rm["everyone"] != nil:
		return "everyone"
	case rm["certificate"] != nil:
		return "certificate"
	case rm["any_valid_service_token"] != nil:
		return "any_valid_service_token"
	}

	if em, ok := rm["email"].(map[string]interface{}); ok {
		email, _ := em["email"].(string)
		return "email:" + email
	}
	if ed, ok := rm["email_domain"].(map[string]interface{}); ok {
		domain, _ := ed["domain"].(string)
		return "email_domain:" + domain
	}
	if grpRule, ok := rm["group"].(map[string]interface{}); ok {
		id, _ := grpRule["id"].(string)
		return "group:" + id
	}
	if ipRule, ok := rm["ip"].(map[string]interface{}); ok {
		ip, _ := ipRule["ip"].(string)
		return "ip:" + ip
	}
	if ipListRule, ok := rm["ip_list"].(map[string]interface{}); ok {
		id, _ := ipListRule["id"].(string)
		return "ip_list:" + id
	}
	if geoRule, ok := rm["geo"].(map[string]interface{}); ok {
		code, _ := geoRule["country_code"].(string)
		return "geo:" + code
	}
	if tokenRule, ok := rm["service_token"].(map[string]interface{}); ok {
		id, _ := tokenRule["token_id"].(string)
		return "service_token:" + id
	}

	// Unrecognized rule type: fall back to its JSON key so the rule's
	// presence is still visible even though this connector can't describe
	// its value.
	for key := range rm {
		return key
	}
	return "unknown"
}

func emailDomain(email string) string {
	idx := strings.LastIndex(email, "@")
	if idx < 0 {
		return ""
	}
	return email[idx+1:]
}
