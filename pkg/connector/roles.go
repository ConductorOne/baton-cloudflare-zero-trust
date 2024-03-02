package connector

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type roleBuilder struct {
	resourceType *v2.ResourceType
	client       *cloudflare.API
	accountId    string
}

var roles []cloudflare.AccountRole
var members []cloudflare.AccountMember

func (r *roleBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// getRoleResource creates a new connector resource for a cloudflare role.
func getRoleResource(ctx context.Context, role cloudflare.AccountRole, resourceTypeRole *v2.ResourceType, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"role_id":   role.ID,
		"role_name": role.Name,
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	ret, err := rs.NewRoleResource(
		role.Name,
		resourceTypeRole,
		role.ID,
		roleTraitOptions,
		rs.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the roles from the database as resource objects.
// Roles include a RoleTrait because they are the 'shape' of a standard group.
func (r *roleBuilder) List(ctx context.Context, parentId *v2.ResourceId, token *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	_, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: r.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	if len(roles) == 0 {
		accountID := cloudflare.ResourceContainer{
			Identifier: r.accountId,
		}
		roles, err = r.client.ListAccountRoles(ctx, &accountID, cloudflare.ListAccountRolesParams{
			ResultInfo: cloudflare.ResultInfo{
				Page:    page,
				PerPage: resourcePageSize,
			},
		})
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to list roles")
		}
	}

	resources := make([]*v2.Resource, 0, len(roles))
	for _, role := range roles {
		resource, err := getRoleResource(ctx, role, roleResourceType, parentId)
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to create role resource")
		}

		resources = append(resources, resource)
	}

	return resources, "", nil, nil
}

func (r *roleBuilder) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	_, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: r.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	if len(roles) == 0 {
		accountID := cloudflare.ResourceContainer{
			Identifier: r.accountId,
		}
		roles, err = r.client.ListAccountRoles(ctx, &accountID, cloudflare.ListAccountRolesParams{
			ResultInfo: cloudflare.ResultInfo{
				Page:    page,
				PerPage: resourcePageSize,
			},
		})
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to list roles")
		}
	}

	for _, role := range roles {
		options := []ent.EntitlementOption{
			ent.WithGrantableTo(roleResourceType),
			ent.WithDisplayName(fmt.Sprintf("%s Role %s", resource.DisplayName, role.Name)),
			ent.WithDescription(fmt.Sprintf("%s of %s Cloudflare role", role.Name, resource.DisplayName)),
		}

		rv = append(rv, ent.NewAssignmentEntitlement(resource, role.Name, options...))
	}

	return rv, "", nil, nil
}

func (r *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var (
		rv   []*v2.Grant
		info cloudflare.ResultInfo
	)
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: r.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	if len(members) == 0 {
		members, info, err = r.client.AccountMembers(ctx, r.accountId, cloudflare.PaginationOptions{
			Page:    page,
			PerPage: resourcePageSize,
		})
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to list users")
		}
	}

	for _, member := range members {
		for _, role := range member.Roles {
			memberCopy := member
			if role.ID != resource.Id.Resource {
				continue
			}
			ur, err := getMemberResource(ctx, &memberCopy.User)
			if err != nil {
				return nil, "", nil, fmt.Errorf("error creating team_member resource for role %s: %w", resource.Id.Resource, err)
			}
			gr := grant.NewGrant(resource, role.Name, ur.Id)
			tr := grant.NewGrant(ur, role.Name, resource.Id)
			rv = append(rv, gr, tr)
		}
	}

	if info.TotalPages <= info.Page {
		return rv, "", nil, nil
	}

	nextPage, err := getPageTokenFromPage(bag, page+1)
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextPage, nil, nil
}

func (r *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	return nil, nil
}

func (r *roleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	return nil, nil
}

func newRoleBuilder(client *cloudflare.API, accountId string) *roleBuilder {
	return &roleBuilder{
		resourceType: roleResourceType,
		client:       client,
		accountId:    accountId,
	}
}
