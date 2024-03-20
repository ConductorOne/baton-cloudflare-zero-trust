package connector

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
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

func getMemberResource(member *cloudflare.AccountMember) (*v2.Resource, error) {
	usr := member.User
	profile := map[string]interface{}{
		"login":      usr.Email,
		"first_name": usr.FirstName,
		"last_name":  usr.LastName,
		"email":      usr.Email,
	}

	userTraits := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED),
		rs.WithUserLogin(usr.Email),
		rs.WithEmail(usr.Email, true),
	}

	displayName := fmt.Sprintf("%s %s", usr.FirstName, usr.LastName)
	if usr.FirstName == "" {
		displayName = usr.Email
	}

	resource, err := rs.NewUserResource(displayName, memberResourceType, usr.ID, userTraits)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns all the members of an account as resource objects.
// Members include a UserTrait because they are the 'shape' of a standard member.
func (m *memberBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var info cloudflare.ResultInfo
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: m.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	members, info, err = m.client.AccountMembers(ctx, m.accountId, cloudflare.PaginationOptions{
		Page:    page,
		PerPage: resourcePageSize,
	})
	if err != nil {
		return nil, "", nil, wrapError(err, "failed to list members")
	}

	resources := make([]*v2.Resource, 0, len(members))
	for _, member := range members {
		memberCopy := member
		resource, err := getMemberResource(&memberCopy)
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to create member resource")
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
	return nil, "", nil, nil
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
