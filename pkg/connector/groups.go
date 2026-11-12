package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/baton-cloudflare-zero-trust/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/session"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const memberRole = "member"

// maxProfileRules caps how many rules of each list are written to a group's
// profile. A List() page carries up to 50 groups, so the profiles add up:
// groups built as one email rule per member, with thousands of rules each,
// would otherwise push a page past the 4 MB gRPC message limit. The full
// count is written alongside.
const maxProfileRules = 25

// List stores every group's rules in the sync's session store, and
// GrantsForResourceType reads them back to evaluate the account members
// against every group in one pass over the member list. The SDK only plans
// grants once resources are synced, so every List page has run by then.
const (
	groupRulesSessionScope = "group_rules:"
	// groupRulesStoredKey is written by every List page. It lives outside
	// groupRulesSessionScope so reading the rules back does not return it.
	// Without it, rules that were never stored would read back as no groups
	// and report every membership as removed.
	groupRulesStoredKey = "group_rules_stored"
)

type groupBuilder struct {
	resourceType *v2.ResourceType
	client       *client.Client
}

func (g *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for a Cloudflare access group.
func newGroupResource(group *client.AccessGroup) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_name": group.Name,
		"group_id":   group.ID,
	}
	addProfileRules(profile, "include", group.Include)
	addProfileRules(profile, "require", group.Require)
	addProfileRules(profile, "exclude", group.Exclude)

	ret, err := rs.NewGroupResource(
		group.Name,
		groupResourceType,
		group.ID,
		nil,
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// addProfileRules writes up to maxProfileRules described rules under
// "<list>_rules" and the list's full length under "<list>_rule_count".
func addProfileRules(profile map[string]interface{}, list string, rules []interface{}) {
	if len(rules) == 0 {
		return
	}
	shown := rules
	if len(shown) > maxProfileRules {
		shown = shown[:maxProfileRules]
	}
	profile[list+"_rules"] = describeAccessRules(shown)
	profile[list+"_rule_count"] = len(rules)
}

// List returns all the access groups from the database as resource objects.
func (g *groupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	groups, next, annos, err := g.client.ListAccessGroups(ctx, opts.PageToken.Token)
	if err != nil {
		return nil, nil, wrapError(err, "failed to list access groups")
	}

	resources := make([]*v2.Resource, 0, len(groups))
	for _, group := range groups {
		resource, err := newGroupResource(group)
		if err != nil {
			return nil, nil, wrapError(err, "failed to create group resource")
		}

		resources = append(resources, resource)
	}

	if err := storeGroupRules(ctx, opts, groups); err != nil {
		return nil, nil, err
	}

	return resources, &rs.SyncOpResults{NextPageToken: next, Annotations: annos}, nil
}

// storeGroupRules writes one page of groups to the session store for
// GrantsForResourceType, and marks the rules as stored.
func storeGroupRules(ctx context.Context, opts rs.SyncOpAttrs, groups []*client.AccessGroup) error {
	if opts.Session == nil {
		return fmt.Errorf("baton-cloudflare-zero-trust: group sync needs a session store")
	}

	stored := make(map[string]client.AccessGroup, len(groups))
	for _, group := range groups {
		// A value over the store's message limit cannot be read back, and on
		// some stores it ends the read early without an error, which would
		// drop every group after it.
		raw, err := json.Marshal(group)
		if err != nil {
			return wrapError(err, "failed to encode group rules")
		}
		if size := len(groupRulesSessionScope) + len(group.ID) + len(raw); size >= sessions.MaxSessionStoreSizeLimit {
			return fmt.Errorf("baton-cloudflare-zero-trust: access group %s has %d bytes of rules, over the %d byte session store limit", group.ID, size, sessions.MaxSessionStoreSizeLimit)
		}

		stored[group.ID] = *group
		logUnevaluatedRules(ctx, group)
	}

	if len(stored) > 0 {
		if err := session.SetManyJSON(ctx, opts.Session, stored, sessions.WithPrefix(groupRulesSessionScope)); err != nil {
			return wrapError(err, "failed to store group rules")
		}
	}

	if err := session.SetJSON(ctx, opts.Session, groupRulesStoredKey, true); err != nil {
		return wrapError(err, "failed to mark group rules as stored")
	}

	return nil
}

// Entitlements is unused; StaticEntitlements defines the membership entitlement for all groups.
func (g *groupBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// StaticEntitlements returns the "member" assignment entitlement template once for all groups.
// The SDK expands this into a per-group entitlement for every group resource.
func (g *groupBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	tmplResource := &v2.Resource{Id: &v2.ResourceId{ResourceType: g.resourceType.Id}}

	// DisplayName is explicitly cleared, not merely left out:
	// NewAssignmentEntitlement defaults it to the slug, and the SDK
	// substitutes the group's own name only when the template's is empty. Left
	// at the default, every group's entitlement would render as "member" with
	// nothing to tell them apart in entitlement search.
	//
	// Description keeps a constant. It is not what distinguishes entitlements,
	// and the group resource carries no description for the SDK to fall back
	// to, so clearing this one would just leave it blank.
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(""),
		ent.WithDescription("Member of this Cloudflare Access group"),
	}

	return []*v2.Entitlement{ent.NewAssignmentEntitlement(tmplResource, memberRole, options...)}, nil, nil
}

// Grants is not called for groups: the type carries TypeScopedGrants, so the
// SDK calls GrantsForResourceType once for the whole type instead.
func (g *groupBuilder) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// groupGrantsCursor is GrantsForResourceType's page token: the first call
// emits the nested-group grants, and each later call evaluates one page of
// members against every group.
type groupGrantsCursor struct {
	NestedDone bool   `json:"nested_done,omitempty"`
	MemberPage string `json:"member_page,omitempty"`
}

// GrantsForResourceType emits membership grants for every group. Cloudflare
// cannot list a group's members, so membership is worked out by evaluating
// each account member against the group's rules. Doing that group by group
// would page the whole member list once per group; here the member list is
// paged once and checked against every group List stored.
func (g *groupBuilder) GrantsForResourceType(ctx context.Context, _ string, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	if opts.Session == nil {
		return nil, nil, fmt.Errorf("baton-cloudflare-zero-trust: group grants need a session store")
	}

	var cursor groupGrantsCursor
	if opts.PageToken.Token != "" {
		if err := json.Unmarshal([]byte(opts.PageToken.Token), &cursor); err != nil {
			return nil, nil, wrapError(err, "failed to decode page token")
		}
	}

	groups, err := g.storedGroups(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	if !cursor.NestedDone {
		var rv []*v2.Grant
		for i := range groups {
			rv = append(rv, g.nestedGroupGrants(ctx, &groups[i])...)
		}
		results, err := nextGroupGrantsPage(groupGrantsCursor{NestedDone: true})
		if err != nil {
			return nil, nil, err
		}
		return rv, results, nil
	}

	members, nextMemberPage, annos, err := g.client.ListAccountMembers(ctx, cursor.MemberPage)
	if err != nil {
		return nil, nil, wrapError(err, "failed to list members")
	}

	var rv []*v2.Grant
	for i := range groups {
		grants, err := g.memberGrants(&groups[i], members)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, grants...)
	}

	if nextMemberPage == "" {
		return rv, &rs.SyncOpResults{Annotations: annos}, nil
	}

	results, err := nextGroupGrantsPage(groupGrantsCursor{NestedDone: true, MemberPage: nextMemberPage})
	if err != nil {
		return nil, nil, err
	}
	results.Annotations = annos
	return rv, results, nil
}

func nextGroupGrantsPage(cursor groupGrantsCursor) (*rs.SyncOpResults, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return nil, wrapError(err, "failed to encode page token")
	}
	return &rs.SyncOpResults{NextPageToken: string(raw)}, nil
}

// storedGroups reads back the groups List stored, ordered by ID so grants are
// emitted in a stable order.
func (g *groupBuilder) storedGroups(ctx context.Context, opts rs.SyncOpAttrs) ([]client.AccessGroup, error) {
	_, stored, err := session.GetJSON[bool](ctx, opts.Session, groupRulesStoredKey)
	if err != nil {
		return nil, wrapError(err, "failed to read group rules marker")
	}
	if !stored {
		return nil, fmt.Errorf("baton-cloudflare-zero-trust: group rules were not stored by the group list step, so membership cannot be evaluated")
	}

	byID, err := session.GetAllJSON[client.AccessGroup](ctx, opts.Session, sessions.WithPrefix(groupRulesSessionScope))
	if err != nil {
		return nil, wrapError(err, "failed to read group rules")
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	groups := make([]client.AccessGroup, 0, len(ids))
	for _, id := range ids {
		groups = append(groups, byID[id])
	}
	return groups, nil
}

// memberGrants returns the grants of group's member entitlement to each of
// members the group's rules admit.
func (g *groupBuilder) memberGrants(group *client.AccessGroup, members []*client.AccountMember) ([]*v2.Grant, error) {
	groupResource := &v2.Resource{Id: &v2.ResourceId{ResourceType: g.resourceType.Id, Resource: group.ID}}
	directIncludeRules, _ := splitIncludeRules(group.Include)

	var rv []*v2.Grant
	for _, member := range members {
		if member.User.ID == "" {
			// A pending invite has no native Cloudflare user ID yet, and
			// userBuilder.List skips it for the same reason. Its email is
			// populated, so it would otherwise match an everyone or
			// email_domain rule and produce a grant whose principal was never
			// synced — and every such grant would share one ID.
			continue
		}

		user := client.AccessUser{
			ID:         member.User.ID,
			Name:       fmt.Sprintf("%s %s", member.User.FirstName, member.User.LastName),
			Email:      member.User.Email,
			AccessSeat: func(seat bool) *bool { return &seat }(false),
		}
		if !matchesDirectRules(group, directIncludeRules, user) {
			continue
		}

		ur, err := newUserResource(user)
		if err != nil {
			return nil, wrapError(err, "failed to create user resource")
		}

		var grantOpts []grant.GrantOption
		// Only a membership backed by an email rule naming this user alone
		// can be revoked; one from an everyone or email_domain rule governs
		// other members too, and removing a group's only Include rule is
		// rejected by Cloudflare. Marking the rest immutable keeps C1 from
		// offering a revoke that Revoke would refuse.
		if include, outcome := revokeDecision(group, user.Email); outcome != revokeRemoveRule || len(include) == 0 {
			grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantImmutable{}))
		}
		rv = append(rv, grant.NewGrant(groupResource, memberRole, ur.Id, grantOpts...))
	}

	return rv, nil
}

// nestedGroupGrants represents each nested-group Include rule as an
// expandable grant against the nested group's own member entitlement, rather
// than flattening it to individual users.
//
// Expansion is a pure union and cannot re-apply this group's Require/Exclude
// to the principals it pulls in, so when either list can narrow membership
// the expandable grant would over-grant: an excluded member of the nested
// group would still be reported as a member here. No grant is emitted in that
// case, which fails closed and reports only the members the direct rules gate.
func (g *groupBuilder) nestedGroupGrants(ctx context.Context, group *client.AccessGroup) []*v2.Grant {
	_, nestedGroupIDs := splitIncludeRules(group.Include)
	if len(nestedGroupIDs) == 0 {
		return nil
	}

	if restrictsNestedExpansion(group) {
		ctxzap.Extract(ctx).Debug(
			"baton-cloudflare-zero-trust: group has both a nested-group Include rule and Require/Exclude rules, which cannot be combined; nested membership is not reported for this group",
			zap.String("group_id", group.ID),
			zap.Int("nested_group_count", len(nestedGroupIDs)),
		)
		return nil
	}

	groupResource := &v2.Resource{Id: &v2.ResourceId{ResourceType: g.resourceType.Id, Resource: group.ID}}
	rv := make([]*v2.Grant, 0, len(nestedGroupIDs))
	for _, nestedGroupID := range nestedGroupIDs {
		nestedGroupResource := &v2.Resource{Id: &v2.ResourceId{ResourceType: g.resourceType.Id, Resource: nestedGroupID}}
		nestedEntitlementID := ent.NewEntitlementID(nestedGroupResource, memberRole)

		// Immutable because Grant and Revoke only take users: the nested
		// group's membership is changed through its own rules.
		rv = append(rv, grant.NewGrant(
			groupResource,
			memberRole,
			nestedGroupResource.Id,
			grant.WithAnnotation(&v2.GrantExpandable{EntitlementIds: []string{nestedEntitlementID}}),
			grant.WithAnnotation(&v2.GrantImmutable{}),
		))
	}

	return rv
}

// logUnevaluatedRules reports the rules on group that this connector cannot
// resolve (nested groups, email lists, IdP claims), which can make the
// reported membership wider or narrower than Cloudflare's. Logged at Debug
// because these lines recur on every sync for as long as the customer's
// configuration contains such a rule. The same condition is documented in
// docs/connector.mdx and surfaced on the group's resource profile, which is
// where an operator is meant to see it.
func logUnevaluatedRules(ctx context.Context, group *client.AccessGroup) {
	l := ctxzap.Extract(ctx)
	directIncludeRules, nestedGroupIDs := splitIncludeRules(group.Include)

	if skipped := unresolvableIdentityRules(group.Require); len(skipped) > 0 {
		l.Debug(
			"baton-cloudflare-zero-trust: group Require rules name identities this connector cannot resolve and were skipped; members that do not satisfy them may still be granted",
			zap.String("group_id", group.ID),
			zap.Strings("skipped_rules", skipped),
		)
	}
	// A group with nothing evaluable in Include reports no members, which
	// reads in an access review as "nobody has access". Keyed off the direct
	// rules and the nested-group IDs rather than the raw Include list: a
	// nested-group rule is not evaluated here either, but its expandable grant
	// does make that membership visible, so a group carrying one is not
	// silent. The check is independent of unresolvableIdentityRules, since a
	// purely contextual Include (an "anyone from the US" group, say) reports
	// nobody too and has no unresolvable identity rule to report.
	if !hasEvaluableRule(directIncludeRules) && len(nestedGroupIDs) == 0 {
		l.Debug(
			"baton-cloudflare-zero-trust: no Include rule on this group can be evaluated, so it reports no members; its membership is not visible to C1",
			zap.String("group_id", group.ID),
			zap.Strings("include_rules", describeRuleList(group.Include)),
		)
	} else if skipped := unresolvableIdentityRules(directIncludeRules); len(skipped) > 0 {
		l.Debug(
			"baton-cloudflare-zero-trust: some Include rules name identities this connector cannot resolve and were skipped; members admitted only by those rules are not reported",
			zap.String("group_id", group.ID),
			zap.Strings("skipped_rules", skipped),
		)
	}
	if skipped := unresolvableIdentityRules(group.Exclude); len(skipped) > 0 {
		l.Debug(
			"baton-cloudflare-zero-trust: group Exclude rules name identities this connector cannot resolve and were skipped; members they should exclude may still be granted",
			zap.String("group_id", group.ID),
			zap.Strings("skipped_rules", skipped),
		)
	}
}

func (g *groupBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Debug(
			"baton-cloudflare-zero-trust: only users can be granted group membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-cloudflare-zero-trust: only users can be granted group membership")
	}

	email, err := getEmailFromUserTrait(principal)
	if err != nil {
		return nil, wrapError(err, "unable to get email from user trait")
	}

	group, _, err := g.client.GetAccessGroup(ctx, entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, wrapError(err, "failed to get access group")
	}

	user := client.AccessUser{Email: email}

	// Already a member is the question, not whether a rule names them
	// specifically: on a group admitting everyone, or their email domain, they
	// have access without a rule of their own and adding one would change
	// nothing except leaving a redundant rule that later blocks their revoke.
	if isMember(&group, group.Include, user) {
		return annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	// Require and Exclude override Include, so adding an Include rule for
	// someone those lists keep out would not grant access: the sync would
	// not emit the grant, the next sync would drop it, and because C1
	// never held a grant it would never issue a revoke — leaving the rule in
	// the customer's policy for good.
	if !satisfiesRequireExclude(&group, user) {
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"baton-cloudflare-zero-trust: a Require or Exclude rule on this group keeps %s out, so adding them to Include would not grant access; change that rule in Cloudflare first",
			email,
		)
	}

	// The update replaces the whole Include list read above, and Access groups
	// have no etag or conditional update. A concurrent Grant or Revoke on the
	// same group, or an edit in the dashboard, landing between the read and
	// the write is overwritten.
	include := append(append([]interface{}{}, group.Include...),
		map[string]interface{}{"email": map[string]interface{}{"email": email}})

	if _, err := g.client.UpdateAccessGroupInclude(ctx, &group, include); err != nil {
		return nil, fmt.Errorf("baton-cloudflare-zero-trust: failed to add user to group: %w", err)
	}

	return nil, nil
}

func (g *groupBuilder) Revoke(ctx context.Context, grantToRevoke *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	principal := grantToRevoke.Principal
	entitlement := grantToRevoke.Entitlement

	if principal.Id.ResourceType != userResourceType.Id {
		l.Debug(
			"baton-cloudflare-zero-trust: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-cloudflare-zero-trust: only users can have group membership revoked")
	}

	email, err := getEmailFromUserTrait(principal)
	if err != nil {
		return nil, wrapError(err, "unable to get email from user trait")
	}

	group, _, err := g.client.GetAccessGroup(ctx, entitlement.Resource.Id.Resource)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, wrapError(err, "failed to get access group")
	}

	include, decision := revokeDecision(&group, email)
	switch decision {
	case revokeBlocked:
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"baton-cloudflare-zero-trust: %s remains a member of this group through a rule that names more than one user; remove that rule in Cloudflare instead",
			email,
		)
	case revokeNotAMember:
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	case revokeRemoveRule:
		// Fall through to the update below.
	}

	// Cloudflare rejects a group with an empty Include list, so removing the
	// last rule cannot be done through an update. Reported as a precondition
	// naming the cause, rather than letting the API error surface as an
	// opaque failure on an otherwise ordinary revoke.
	if len(include) == 0 {
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"baton-cloudflare-zero-trust: removing %s would leave this group with no Include rules, which Cloudflare rejects; delete or edit the group in Cloudflare instead",
			email,
		)
	}

	// Same unguarded read-modify-write as Grant.
	if _, err := g.client.UpdateAccessGroupInclude(ctx, &group, include); err != nil {
		if status.Code(err) == codes.NotFound {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("baton-cloudflare-zero-trust: failed to remove user from group: %w", err)
	}

	return nil, nil
}

// revokeOutcome is what Revoke can do about a membership.
type revokeOutcome int

const (
	// revokeRemoveRule: an Include rule names this address and nothing else
	// admits them, so dropping that rule revokes the membership.
	revokeRemoveRule revokeOutcome = iota
	// revokeBlocked: the user stays a member through a rule that names more
	// than one person, which cannot be edited on their behalf.
	revokeBlocked
	// revokeNotAMember: no rule admits them, so there is nothing to revoke.
	revokeNotAMember
)

// revokeDecision works out what Revoke can do about email's membership of grp,
// and returns the Include list to write when the answer is revokeRemoveRule.
//
// Dropping the rule that names an address is only a revoke if nothing else
// still admits them: an email_domain or everyone rule governs other members
// too, so reporting success would claim a removal that did not happen and that
// the next sync would undo. Require and Exclude are applied as well, so a user
// those lists keep out is reported as not a member rather than sending an
// operator after an Include rule that is not granting them anything.
func revokeDecision(grp *client.AccessGroup, email string) ([]interface{}, revokeOutcome) {
	user := client.AccessUser{Email: email}

	// Nothing to revoke if the rules this connector evaluates do not admit
	// them in the first place. Checked before anything else: a user kept out
	// by Require or Exclude can still have an Include rule naming them, and
	// removing it would be editing a rule that grants them nothing.
	if !isMember(grp, grp.Include, user) {
		return nil, revokeNotAMember
	}

	include, found := filterIncludeEmail(grp.Include, email)

	// Membership that survives without a rule naming this address comes from
	// one governing other members too, which cannot be edited on their behalf.
	if !found || isMember(grp, include, user) {
		return include, revokeBlocked
	}

	return include, revokeRemoveRule
}

// filterIncludeEmail rebuilds a group's Include list without the rule naming
// one specific address, reporting whether such a rule was there. Every other
// rule is carried over untouched: a group's membership can come from
// email_domain, everyone or a nested group as well, and dropping those rules
// here would delete them from the group on the update that follows.
func filterIncludeEmail(include []interface{}, email string) ([]interface{}, bool) {
	out := make([]interface{}, 0, len(include))
	found := false
	for _, rule := range include {
		if ruleEmail, ok := includeRuleEmail(rule); ok && strings.EqualFold(ruleEmail, email) {
			found = true
			continue
		}
		out = append(out, rule)
	}
	return out, found
}

// includeRuleEmail returns the address named by an "email" Include rule.
// Rules of any other type, and malformed ones, report false rather than
// panicking on a type assertion: an Access group's Include list can hold
// email_domain, everyone, geo, ip or nested group rules too.
func includeRuleEmail(rule interface{}) (string, bool) {
	rm, ok := rule.(map[string]interface{})
	if !ok {
		return "", false
	}

	em, ok := rm["email"].(map[string]interface{})
	if !ok {
		return "", false
	}

	address, ok := em["email"].(string)
	if !ok || address == "" {
		return "", false
	}

	return address, true
}

func newGroupBuilder(c *client.Client) *groupBuilder {
	return &groupBuilder{
		resourceType: groupResourceType,
		client:       c,
	}
}
