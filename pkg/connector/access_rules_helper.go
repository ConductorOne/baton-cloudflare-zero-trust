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
// Only some rule types can be evaluated here, and the ones that cannot are
// treated as unevaluable rather than as non-matching. The distinction
// matters: each list combines its rules with a boolean operator, and an
// unevaluable rule is skipped so it acts as that operator's neutral element
// and cannot change the list's answer. Reporting "does not match" instead
// would change it — under Require's AND a single unevaluable rule would drop
// every member of the group, asserting an absence of access the connector
// has no basis for.
//
// Rules fall into three classes:
//
//   - Evaluable identity rules ("everyone", "email", "email_domain") name
//     users by an attribute the sync already has, and are evaluated.
//
//   - Contextual rules ("ip", "geo", "device_posture", "auth_method", ...)
//     constrain the request — where it comes from, how it authenticated —
//     not who is making it. Cloudflare evaluates them per request, so they
//     cannot be resolved at sync time by anyone, and they do not narrow
//     membership: C1 models who a policy grants access to, not the
//     conditions under which that access applies.
//
//   - Unresolvable identity rules ("group", "email_list", IdP claims like
//     "okta"/"gsuite"/"saml", service tokens) do name identities, but in a
//     directory this connector cannot read. Skipping them can over-report
//     membership, which is why every group with one is logged.
//
// A "group" rule in Include is the exception: it is not evaluated here
// either, but splitIncludeRules hands it to groups.go, which emits a
// GrantExpandable grant so C1's own graph expansion resolves it. That
// expansion is a union and cannot honor the outer group's Require/Exclude,
// so it is suppressed when those lists can narrow membership — see
// restrictsNestedExpansion.

// ruleEvaluation is the outcome of testing one rule against one user.
type ruleEvaluation int

const (
	ruleNoMatch ruleEvaluation = iota
	ruleMatch
	ruleUnevaluable
)

// contextualRuleKeys constrain the request rather than the identity making
// it. They are unevaluable at sync time and, by design, never narrow the
// membership this connector reports.
var contextualRuleKeys = map[string]bool{
	"auth_context":        true,
	"auth_method":         true,
	"certificate":         true,
	"common_name":         true,
	"device_posture":      true,
	"external_evaluation": true,
	"geo":                 true,
	"ip":                  true,
	"ip_list":             true,
	"login_method":        true,
}

// ruleKey returns a rule's single JSON key ("email", "geo", ...), or "" if
// the rule isn't shaped like one.
func ruleKey(rule interface{}) string {
	rm, ok := rule.(map[string]interface{})
	if !ok || len(rm) == 0 {
		return ""
	}
	for key := range rm {
		return key
	}
	return ""
}

// isContextualRule reports whether a rule constrains the request rather than
// the identity. Used to log the benign unevaluable rules separately from the
// identity ones, which are the rules that can cause over-reporting.
func isContextualRule(rule interface{}) bool {
	return contextualRuleKeys[ruleKey(rule)]
}

// evaluateRule tests one rule against one user, reporting ruleUnevaluable for
// any rule type this connector cannot resolve. See the package comment above
// for why that is distinct from ruleNoMatch.
func evaluateRule(rule interface{}, user cloudflare.AccessUser) ruleEvaluation {
	rm, ok := rule.(map[string]interface{})
	if !ok {
		return ruleUnevaluable
	}

	if _, ok := rm["everyone"]; ok {
		return ruleMatch
	}

	if em, ok := rm["email"].(map[string]interface{}); ok {
		email, _ := em["email"].(string)
		if email != "" && strings.EqualFold(email, user.Email) {
			return ruleMatch
		}
		return ruleNoMatch
	}

	if ed, ok := rm["email_domain"].(map[string]interface{}); ok {
		domain, _ := ed["domain"].(string)
		if domain != "" && strings.EqualFold(emailDomain(user.Email), domain) {
			return ruleMatch
		}
		return ruleNoMatch
	}

	return ruleUnevaluable
}

// isEvaluableRule reports whether this connector can decide the rule against
// a user at all, independent of any particular user.
func isEvaluableRule(rule interface{}) bool {
	return evaluateRule(rule, cloudflare.AccessUser{}) != ruleUnevaluable
}

// ruleMatchesUser reports whether a rule positively matches a user. An
// unevaluable rule is not a match; callers that combine rules must use
// anyRuleMatches/allRulesMatch, which skip unevaluable rules rather than
// counting them as misses.
func ruleMatchesUser(rule interface{}, user cloudflare.AccessUser) bool {
	return evaluateRule(rule, user) == ruleMatch
}

// anyRuleMatches reports whether any rule matches (OR). Unevaluable rules are
// skipped: false is the neutral element of OR, so they neither grant nor
// withhold membership on their own.
func anyRuleMatches(rules []interface{}, user cloudflare.AccessUser) bool {
	for _, rule := range rules {
		if evaluateRule(rule, user) == ruleMatch {
			return true
		}
	}
	return false
}

// allRulesMatch reports whether every rule matches (AND). Unevaluable rules
// are skipped: true is the neutral element of AND, so a rule this connector
// cannot read never empties the group.
func allRulesMatch(rules []interface{}, user cloudflare.AccessUser) bool {
	for _, rule := range rules {
		if evaluateRule(rule, user) == ruleNoMatch {
			return false
		}
	}
	return true
}

// hasEvaluableRule reports whether any rule in the list can be decided at all.
// An Include list with none is the case where OR's neutral element stops being
// harmless: with nothing to match, the group reports no members, which reads
// in an access review as "nobody has access" rather than "we cannot tell".
func hasEvaluableRule(rules []interface{}) bool {
	for _, rule := range rules {
		if isEvaluableRule(rule) {
			return true
		}
	}
	return false
}

// matchesDirectRules is the single definition of membership this connector
// works from: an Include rule must admit the user and Require/Exclude must not
// keep them out. Grants() calls it per member with the split rules it already
// computed; isMember is the convenience form for callers holding a raw Include
// list.
//
// Nested-group Include rules are deliberately outside this question. They are
// resolved by C1's graph expansion rather than here, so a user who is a member
// only through nesting is invisible to it.
func matchesDirectRules(grp *cloudflare.AccessGroup, directInclude []interface{}, user cloudflare.AccessUser) bool {
	return anyRuleMatches(directInclude, user) && satisfiesRequireExclude(grp, user)
}

// isMember reports whether the rules this connector can evaluate admit user to
// grp, considering include as its Include list. Passing a filtered list
// answers "would they still be a member if these rules were written".
func isMember(grp *cloudflare.AccessGroup, include []interface{}, user cloudflare.AccessUser) bool {
	direct, _ := splitIncludeRules(include)
	return matchesDirectRules(grp, direct, user)
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
// Include rules. Rules this connector cannot evaluate are skipped in both
// lists — see the package doc comment above.
func satisfiesRequireExclude(grp *cloudflare.AccessGroup, user cloudflare.AccessUser) bool {
	return allRulesMatch(grp.Require, user) && !anyRuleMatches(grp.Exclude, user)
}

// unresolvableIdentityRules returns a description of every rule that names
// identities this connector cannot resolve ("group", "email_list", IdP
// claims, service tokens). Those rules are skipped during evaluation, so a
// group carrying one may report more members than Cloudflare would admit;
// Grants() logs them so the gap is visible at sync time rather than only in
// the docs. Contextual rules are excluded: skipping those is by design, not
// a gap.
func unresolvableIdentityRules(rules []interface{}) []string {
	var described []string
	for _, rule := range rules {
		if isEvaluableRule(rule) || isContextualRule(rule) {
			continue
		}
		described = append(described, describeAccessRule(rule))
	}
	return described
}

// describeAccessRules renders a group's Include/Require/Exclude rules as
// short human-readable strings for the group's resource profile, so
// customers can see how a group is configured without pulling the raw
// Cloudflare API response. Returned as []interface{} since that's the list
// type structpb.NewStruct accepts for a profile field.
func describeAccessRules(rules []interface{}) []interface{} {
	described := make([]interface{}, 0, len(rules))
	for _, rule := range describeRuleList(rules) {
		described = append(described, rule)
	}
	return described
}

// describeRuleList renders rules for a log field, where describeAccessRules'
// []interface{} shape is not wanted.
func describeRuleList(rules []interface{}) []string {
	described := make([]string, 0, len(rules))
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

// restrictsNestedExpansion reports whether a group's Require/Exclude lists
// can narrow the membership it inherits from a nested Include group.
//
// A nested Include rule is emitted as a GrantExpandable grant, which the
// expansion engine resolves as a pure union: every principal holding the
// nested group's member entitlement gains the outer group's too. There is
// no hook for re-applying the outer group's Require/Exclude to those
// expanded principals, so expansion only reflects Cloudflare's semantics
// when neither list can filter anyone out.
//
// Only a rule that actually narrows membership counts. A rule this connector
// skips during evaluation cannot filter the direct members either, so
// suppressing expansion over it would withhold membership on the strength of
// a rule that changed nothing. An "everyone" Require is likewise no
// restriction, since every user satisfies it by definition.
func restrictsNestedExpansion(grp *cloudflare.AccessGroup) bool {
	for _, rule := range grp.Exclude {
		if isEvaluableRule(rule) {
			return true
		}
	}

	for _, rule := range grp.Require {
		if !isEvaluableRule(rule) {
			continue
		}
		if ruleKey(rule) != "everyone" {
			return true
		}
	}

	return false
}
