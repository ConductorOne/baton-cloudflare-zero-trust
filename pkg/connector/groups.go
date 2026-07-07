package connector

import (
	"context"
	"fmt"

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

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	ret, err := rs.NewGroupResource(
		group.Name,
		groupResourceType,
		group.ID,
		groupTraitOptions,
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

func (g *groupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	var rv []*v2.Entitlement
	options := []ent.EntitlementOption{
		// groupResourceType is grantable too: a group nested via an
		// Include "group" rule is granted this entitlement itself,
		// annotated GrantExpandable, rather than flattened to its members.
		ent.WithGrantableTo(userResourceType, groupResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s Group %s", resource.DisplayName, memberRole)),
		ent.WithDescription(fmt.Sprintf("%s of %s Cloudflare group", memberRole, resource.DisplayName)),
	}

	rv = append(rv, ent.NewAssignmentEntitlement(resource, memberRole, options...))

	return rv, nil, nil
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
	groupCache := map[string]*cloudflare.AccessGroup{group.ID: &group}

	for _, user := range users {
		userCopy := user

		included, err := anyRuleMatches(ctx, g.client, g.accountId, directIncludeRules, userCopy, groupCache, map[string]bool{})
		if err != nil {
			return nil, nil, wrapError(err, "failed to evaluate group include rules")
		}
		if !included {
			continue
		}

		satisfied, err := satisfiesRequireExclude(ctx, g.client, g.accountId, &group, userCopy, groupCache)
		if err != nil {
			return nil, nil, wrapError(err, "failed to evaluate group require/exclude rules")
		}
		if !satisfied {
			continue
		}

		ur, err := newUserResource(userCopy)
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
	if page == 0 {
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

	nextPage, err := getPageTokenFromPage(bag, page+1)
	if err != nil {
		return nil, nil, err
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPage}, nil
}

func (g *groupBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
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
		l.Warn(
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
