package connector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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

	nextPage, err := bag.NextToken(strconv.Itoa(info.Page + 1))
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

	var grants []interface{}
	// existing emails in group.
	grants = append(grants, group.Include...)
	// new access email to add to group.
	grants = append(grants, map[string]interface{}{"email": map[string]interface{}{"email": email}})

	_, err = g.client.UpdateAccessGroup(ctx, cloudflare.AccountIdentifier(g.accountId), cloudflare.UpdateAccessGroupParams{
		ID:      entitlement.Resource.Id.Resource,
		Include: grants,
	})
	if err != nil {
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

	var grants []interface{}
	// send only the grants that do not match the email to revoke.
	for _, g := range group.Include {
		value := g.(map[string]interface{})["email"].(map[string]interface{})["email"]
		if value != email {
			grants = append(grants, g)
		}
	}

	_, err = g.client.UpdateAccessGroup(ctx, cloudflare.AccountIdentifier(g.accountId), cloudflare.UpdateAccessGroupParams{
		ID:      entitlement.Resource.Id.Resource,
		Include: grants,
	})

	if err != nil {
		return nil, fmt.Errorf("baton-cloudflare-zero-trust: failed to remove user from group: %w", err)
	}

	return nil, nil
}

func newGroupBuilder(client *cloudflare.API, accountId string) *groupBuilder {
	return &groupBuilder{
		resourceType: groupResourceType,
		client:       client,
		accountId:    accountId,
	}
}
