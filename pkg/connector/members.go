package connector

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

type memberBuilder struct {
	client       *cloudflare.API
	resourceType *v2.ResourceType
	accountId    string
}

func (m *memberBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return m.resourceType
}

// List returns all the members of an account as resource objects.
// Members include a UserTrait because they are the 'shape' of a standard member.
func (m *memberBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var info cloudflare.ResultInfo
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: m.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	memberUsers, info, err := m.client.AccountMembers(ctx, m.accountId, cloudflare.PaginationOptions{
		Page:    page,
		PerPage: resourcePageSize,
	})
	if err != nil {
		return nil, "", nil, wrapError(err, "failed to list members")
	}

	resources := make([]*v2.Resource, 0, len(memberUsers))
	for _, memberUser := range memberUsers {
		accUser := cloudflare.AccessUser{
			ID:    memberUser.User.ID,
			Name:  fmt.Sprintf("%s %s", memberUser.User.FirstName, memberUser.User.LastName),
			Email: memberUser.User.Email,
			AccessSeat: func(seat bool) *bool {
				return &seat
			}(false),
		}
		resource, err := newUserResource(accUser)
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
