package connector

import (
	"context"
	"strings"

	"github.com/cloudflare/cloudflare-go"
)

// groupIncludesUser evaluates whether a user satisfies a Cloudflare Access
// Group's Include/Require/Exclude rules:
//   - Include is OR: at least one rule must match.
//   - Require is AND: every rule must match.
//   - Exclude is NOT: no rule may match.
//
// "group" rules reference another Access Group by ID and are evaluated
// recursively with the same combinator semantics. cache avoids re-fetching a
// nested group already seen during this evaluation; visiting guards against
// reference cycles between groups (A includes B, B includes A).
func groupIncludesUser(
	ctx context.Context,
	client *cloudflare.API,
	accountId string,
	grp *cloudflare.AccessGroup,
	user cloudflare.AccessUser,
	cache map[string]*cloudflare.AccessGroup,
	visiting map[string]bool,
) (bool, error) {
	if visiting[grp.ID] {
		return false, nil
	}
	visiting[grp.ID] = true
	defer delete(visiting, grp.ID)

	included, err := anyRuleMatches(ctx, client, accountId, grp.Include, user, cache, visiting)
	if err != nil {
		return false, err
	}
	if !included {
		return false, nil
	}

	for _, rule := range grp.Require {
		matches, err := ruleMatchesUser(ctx, client, accountId, rule, user, cache, visiting)
		if err != nil {
			return false, err
		}
		if !matches {
			return false, nil
		}
	}

	excluded, err := anyRuleMatches(ctx, client, accountId, grp.Exclude, user, cache, visiting)
	if err != nil {
		return false, err
	}
	if excluded {
		return false, nil
	}

	return true, nil
}

func anyRuleMatches(
	ctx context.Context,
	client *cloudflare.API,
	accountId string,
	rules []interface{},
	user cloudflare.AccessUser,
	cache map[string]*cloudflare.AccessGroup,
	visiting map[string]bool,
) (bool, error) {
	for _, rule := range rules {
		matches, err := ruleMatchesUser(ctx, client, accountId, rule, user, cache, visiting)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

// ruleMatchesUser evaluates a single Include/Require/Exclude rule against a
// user. Only the rule types this connector grants access for are supported:
// "email", "email_domain", "everyone", and nested "group" references. Any
// other rule type (ip, certificate, IdP-group claims, etc.) is treated as
// non-matching rather than an error, since it doesn't identify a user by
// email and this connector's grants are keyed on user identity.
func ruleMatchesUser(
	ctx context.Context,
	client *cloudflare.API,
	accountId string,
	rule interface{},
	user cloudflare.AccessUser,
	cache map[string]*cloudflare.AccessGroup,
	visiting map[string]bool,
) (bool, error) {
	rm, ok := rule.(map[string]interface{})
	if !ok {
		return false, nil
	}

	if _, ok := rm["everyone"]; ok {
		return true, nil
	}

	if em, ok := rm["email"].(map[string]interface{}); ok {
		email, _ := em["email"].(string)
		return email != "" && strings.EqualFold(email, user.Email), nil
	}

	if ed, ok := rm["email_domain"].(map[string]interface{}); ok {
		domain, _ := ed["domain"].(string)
		return domain != "" && strings.EqualFold(emailDomain(user.Email), domain), nil
	}

	if grpRule, ok := rm["group"].(map[string]interface{}); ok {
		groupId, _ := grpRule["id"].(string)
		if groupId == "" {
			return false, nil
		}
		nested, err := getAccessGroupCached(ctx, client, accountId, groupId, cache)
		if err != nil {
			return false, err
		}
		return groupIncludesUser(ctx, client, accountId, nested, user, cache, visiting)
	}

	return false, nil
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
func splitIncludeRules(rules []interface{}) (direct []interface{}, nestedGroupIDs []string) {
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
// Include rules. Require/Exclude rules referencing a nested group are
// evaluated recursively as a per-user membership check (not flattened),
// since they gate a single already-identified user rather than enumerate an
// entire nested group's roster.
func satisfiesRequireExclude(
	ctx context.Context,
	client *cloudflare.API,
	accountId string,
	grp *cloudflare.AccessGroup,
	user cloudflare.AccessUser,
	cache map[string]*cloudflare.AccessGroup,
) (bool, error) {
	for _, rule := range grp.Require {
		matches, err := ruleMatchesUser(ctx, client, accountId, rule, user, cache, map[string]bool{})
		if err != nil {
			return false, err
		}
		if !matches {
			return false, nil
		}
	}

	excluded, err := anyRuleMatches(ctx, client, accountId, grp.Exclude, user, cache, map[string]bool{})
	if err != nil {
		return false, err
	}

	return !excluded, nil
}

func getAccessGroupCached(
	ctx context.Context,
	client *cloudflare.API,
	accountId string,
	groupId string,
	cache map[string]*cloudflare.AccessGroup,
) (*cloudflare.AccessGroup, error) {
	if grp, ok := cache[groupId]; ok {
		return grp, nil
	}
	grp, err := client.GetAccessGroup(ctx, cloudflare.AccountIdentifier(accountId), groupId)
	if err != nil {
		return nil, wrapError(err, "failed to get nested access group")
	}
	cache[groupId] = &grp
	return &grp, nil
}

func emailDomain(email string) string {
	idx := strings.LastIndex(email, "@")
	if idx < 0 {
		return ""
	}
	return email[idx+1:]
}
