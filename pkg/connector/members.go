package connector

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type memberBuilder struct {
	client       *cloudflare.API
	resourceType *v2.ResourceType
	accountId    string
}

func (m *memberBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return m.resourceType
}

func getMemberResource(ctx context.Context, member *cloudflare.AccountMember) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"login":      member.User.Email,
		"first_name": member.User.FirstName,
		"last_name":  member.User.LastName,
		"email":      member.User.Email,
	}

	userTraits := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED),
		rs.WithUserLogin(member.User.Email),
		rs.WithEmail(member.User.Email, true),
	}

	displayName := member.User.FirstName + " " + member.User.LastName

	if member.User.FirstName == "" {
		displayName = member.User.Email
	}

	resource, err := rs.NewUserResource(displayName, memberResourceType, member.ID, userTraits)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns all the members of an account as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (m *memberBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var info cloudflare.ResultInfo
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: m.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	if len(members) == 0 {
		members, info, err = m.client.AccountMembers(ctx, m.accountId, cloudflare.PaginationOptions{
			Page:    page,
			PerPage: resourcePageSize,
		})
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to list users")
		}
	}

	resources := make([]*v2.Resource, 0, len(members))
	for _, member := range members {
		memberCopy := member
		resource, err := getMemberResource(ctx, &memberCopy)
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to create user resource")
		}

		resources = append(resources, resource)
	}

	if info.TotalPages <= info.Page {
		return resources, "", nil, nil
	}

	nextPage, err := getPageTokenFromPage(bag, page+1)
	if err != nil {
		return nil, "", nil, err
	}

	return resources, nextPage, nil, nil
}

// Entitlements always returns an empty slice for users.
func (m *memberBuilder) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	_, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: m.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	if len(roles) == 0 {
		accountID := cloudflare.ResourceContainer{
			Identifier: m.accountId,
		}
		roles, err = m.client.ListAccountRoles(ctx, &accountID, cloudflare.ListAccountRolesParams{
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
			ent.WithGrantableTo(memberResourceType),
			ent.WithDisplayName(fmt.Sprintf("%s Member %s", resource.DisplayName, role.Name)),
			ent.WithDescription(fmt.Sprintf("%s of %s Cloudflare member", role.Name, resource.DisplayName)),
		}

		rv = append(rv, ent.NewAssignmentEntitlement(resource, role.Name, options...))
	}

	return rv, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (m *memberBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newMemberBuilder(client *cloudflare.API, accountId string) *memberBuilder {
	return &memberBuilder{
		resourceType: memberResourceType,
		client:       client,
		accountId:    accountId,
	}
}
