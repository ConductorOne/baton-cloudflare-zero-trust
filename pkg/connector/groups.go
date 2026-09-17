package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const memberRole = "member"

type groupBuilder struct {
	resourceType *v2.ResourceType
	client       *cloudflare.API
	accountId    string
}

func (g *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for a Cloudflare access group.
func newGroupResource(group *cloudflare.AccessGroup) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_name": group.Name,
		"group_id":   group.ID,
	}
	if len(group.Include) > 0 {
		profile["include_rules"] = describeAccessRules(group.Include)
	}
	if len(group.Require) > 0 {
		profile["require_rules"] = describeAccessRules(group.Require)
	}
	if len(group.Exclude) > 0 {
		profile["exclude_rules"] = describeAccessRules(group.Exclude)
	}

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

// List returns all the access groups from the database as resource objects.
func (g *groupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, _ rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	groups, _, err := g.client.ListAccessGroups(ctx, cloudflare.AccountIdentifier(g.accountId), cloudflare.ListAccessGroupsParams{})
	if err != nil {
		return nil, nil, wrapError(err, "failed to list access groups")
	}

	resources := make([]*v2.Resource, 0, len(groups))
	for _, group := range groups {
		groupCopy := group
		resource, err := newGroupResource(&groupCopy)
		if err != nil {
			return nil, nil, wrapError(err, "failed to create group resource")
		}

		resources = append(resources, resource)
	}

	return resources, nil, nil
}

// Entitlements is unused; StaticEntitlements defines the membership entitlement for all groups.
func (g *groupBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// StaticEntitlements returns the "member" assignment entitlement template once for all groups.
// The SDK expands this into a per-group entitlement for every group resource.
func (g *groupBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	tmplResource := &v2.Resource{Id: &v2.ResourceId{ResourceType: g.resourceType.Id}}

	options := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("Group %s", memberRole)),
		ent.WithDescription(fmt.Sprintf("%s of Cloudflare group", memberRole)),
	}

	return []*v2.Entitlement{ent.NewAssignmentEntitlement(tmplResource, memberRole, options...)}, nil, nil
}

func (g *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	var (
		users []cloudflare.AccessUser
		rv    []*v2.Grant
		info  cloudflare.ResultInfo
	)
	group, err := g.client.GetAccessGroup(ctx, cloudflare.AccountIdentifier(g.accountId), resource.Id.Resource)
	if err != nil {
		return nil, nil, wrapError(err, "failed to get access group")
	}

	bag, page, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: g.resourceType.Id})
	if err != nil {
		return nil, nil, err
	}

	// An empty page token parses to 0, which is both this method's "first
	// call" signal and an invalid Cloudflare page number: PaginationOptions.Page
	// is omitempty, so 0 drops the parameter and the API serves page 1 anyway.
	// Capture the signal before normalizing, so the page number sent upstream
	// and the one reported back in ResultInfo agree from the first call.
	firstPage := page == 0
	if page == 0 {
		page = 1
	}

	memberUsers, info, err := g.client.AccountMembers(ctx, g.accountId, cloudflare.PaginationOptions{
		Page:    page,
		PerPage: resourcePageSize,
	})
	if err != nil {
		return nil, nil, wrapError(err, "failed to list members")
	}

	for _, memberUser := range memberUsers {
		accUser := cloudflare.AccessUser{
			ID:    memberUser.User.ID,
			Name:  fmt.Sprintf("%s %s", memberUser.User.FirstName, memberUser.User.LastName),
			Email: memberUser.User.Email,
			AccessSeat: func(seat bool) *bool {
				return &seat
			}(false),
		}
		users = append(users, accUser)
	}

	directIncludeRules, nestedGroupIDs := splitIncludeRules(group.Include)

	// Rules naming identities this connector cannot resolve (nested groups,
	// email lists, IdP claims) are skipped during evaluation, so this group's
	// membership may be wider than Cloudflare would admit. Logged once per
	// group, on the first page, rather than on every page of members, and at
	// Debug because these lines recur on every sync for as long as the
	// customer's Cloudflare configuration contains such a rule. The same
	// condition is documented in docs/connector.mdx and surfaced on the
	// group's resource profile, which is where an operator is meant to see it.
	if firstPage {
		if skipped := unresolvableIdentityRules(group.Require); len(skipped) > 0 {
			ctxzap.Extract(ctx).Debug(
				"baton-cloudflare-zero-trust: group Require rules name identities this connector cannot resolve and were skipped; members that do not satisfy them may still be granted",
				zap.String("group_id", group.ID),
				zap.Strings("skipped_rules", skipped),
			)
		}
		if skipped := unresolvableIdentityRules(group.Exclude); len(skipped) > 0 {
			ctxzap.Extract(ctx).Debug(
				"baton-cloudflare-zero-trust: group Exclude rules name identities this connector cannot resolve and were skipped; members they should exclude may still be granted",
				zap.String("group_id", group.ID),
				zap.Strings("skipped_rules", skipped),
			)
		}
	}

	for _, user := range users {
		if !anyRuleMatches(directIncludeRules, user) {
			continue
		}
		if !satisfiesRequireExclude(&group, user) {
			continue
		}

		ur, err := newUserResource(user)
		if err != nil {
			return nil, nil, wrapError(err, "failed to create user resource")
		}
		gr := grant.NewGrant(resource, memberRole, ur.Id)
		rv = append(rv, gr)
	}

	// Nested-group Include rules are represented as expandable grants
	// against the nested group's own member entitlement, not flattened to
	// individual users. Emit them only once, on the first page, since the
	// grant is deterministic and independent of member pagination.
	//
	// Expansion is a pure union and cannot re-apply this group's
	// Require/Exclude to the principals it pulls in, so when either list
	// can narrow membership the expandable grant would over-grant: an
	// excluded member of the nested group would still be reported as a
	// member here. Skip it in that case and fail closed, reporting only
	// the members the direct rules above have already gated.
	if firstPage && restrictsNestedExpansion(&group) && len(nestedGroupIDs) > 0 {
		ctxzap.Extract(ctx).Debug(
			"baton-cloudflare-zero-trust: group has both a nested-group Include rule and Require/Exclude rules, which cannot be combined; nested membership is not reported for this group",
			zap.String("group_id", group.ID),
			zap.Int("nested_group_count", len(nestedGroupIDs)),
		)
		nestedGroupIDs = nil
	}

	if firstPage {
		for _, nestedGroupID := range nestedGroupIDs {
			nestedGroupResource := &v2.Resource{Id: &v2.ResourceId{ResourceType: g.resourceType.Id, Resource: nestedGroupID}}
			nestedEntitlementID := ent.NewEntitlementID(nestedGroupResource, memberRole)

			gr := grant.NewGrant(
				resource,
				memberRole,
				nestedGroupResource.Id,
				grant.WithAnnotation(&v2.GrantExpandable{EntitlementIds: []string{nestedEntitlementID}}),
			)
			rv = append(rv, gr)
		}
	}

	if info.TotalPages <= info.Page {
		return rv, nil, nil
	}

	nextPage, err := bag.NextToken(strconv.Itoa(page + 1))
	if err != nil {
		return nil, nil, err
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPage}, nil
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

	group, err := g.client.GetAccessGroup(ctx, cloudflare.AccountIdentifier(g.accountId), entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, wrapError(err, "failed to get access group")
	}

	// Exclude overrides Include, so adding an Include rule for someone the
	// group excludes would not grant them access: Grants() would refuse to
	// emit the grant and the next sync would drop it again. Checked before
	// the already-present check, since a principal who is both named in
	// Include and excluded does not have access either.
	if anyRuleMatches(group.Exclude, cloudflare.AccessUser{Email: email}) {
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"baton-cloudflare-zero-trust: an Exclude rule on this group blocks %s, so adding them to Include would not grant access; remove that rule in Cloudflare first",
			email,
		)
	}

	for _, rule := range group.Include {
		if ruleEmail, ok := includeRuleEmail(rule); ok && strings.EqualFold(ruleEmail, email) {
			return annotations.New(&v2.GrantAlreadyExists{}), nil
		}
	}

	include := append(append([]interface{}{}, group.Include...),
		map[string]interface{}{"email": map[string]interface{}{"email": email}})

	if err := g.updateAccessGroupInclude(ctx, &group, include); err != nil {
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

	group, err := g.client.GetAccessGroup(ctx, cloudflare.AccountIdentifier(g.accountId), entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, wrapError(err, "failed to get access group")
	}

	include, found := filterIncludeEmail(group.Include, email)
	if !found {
		// The grant may have come from an email_domain or everyone rule
		// instead. Removing it would mean editing a rule that governs other
		// members too, so refuse the revoke rather than report a removal that
		// did not happen and that the next sync would undo.
		if anyRuleMatches(group.Include, cloudflare.AccessUser{Email: email}) {
			return nil, status.Errorf(
				codes.Unimplemented,
				"baton-cloudflare-zero-trust: %s is a member of this group through a rule that names more than one user; remove that rule in Cloudflare instead",
				email,
			)
		}

		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	if err := g.updateAccessGroupInclude(ctx, &group, include); err != nil {
		return nil, fmt.Errorf("baton-cloudflare-zero-trust: failed to remove user from group: %w", err)
	}

	return nil, nil
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

// updateAccessGroupInclude replaces a group's Include list, carrying the rest
// of the group over unchanged. UpdateAccessGroupParams serializes Name,
// Require and Exclude without omitempty, so sending only Include would write
// an empty name and clear both other rule lists.
func (g *groupBuilder) updateAccessGroupInclude(ctx context.Context, group *cloudflare.AccessGroup, include []interface{}) error {
	_, err := g.client.UpdateAccessGroup(ctx, cloudflare.AccountIdentifier(g.accountId), cloudflare.UpdateAccessGroupParams{
		ID:      group.ID,
		Name:    group.Name,
		Include: include,
		Require: group.Require,
		Exclude: group.Exclude,
	})
	return err
}

func newGroupBuilder(client *cloudflare.API, accountId string) *groupBuilder {
	return &groupBuilder{
		resourceType: groupResourceType,
		client:       client,
		accountId:    accountId,
	}
}
