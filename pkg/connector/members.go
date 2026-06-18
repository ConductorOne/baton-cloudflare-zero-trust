package connector

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
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

// List returns all the members of an account as resource objects.
// Members include a UserTrait because they are the 'shape' of a standard member.
func (m *memberBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	var info cloudflare.ResultInfo
	bag, page, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: m.resourceType.Id})
	if err != nil {
		return nil, nil, err
	}

	memberUsers, info, err := m.client.AccountMembers(ctx, m.accountId, cloudflare.PaginationOptions{
		Page:    page,
		PerPage: resourcePageSize,
	})
	if err != nil {
		return nil, nil, wrapError(err, "failed to list members")
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
			return nil, nil, wrapError(err, "failed to create user resource")
		}

		resources = append(resources, resource)
	}

	if info.TotalPages <= info.Page {
		return resources, nil, nil
	}

	nextPage, err := getPageTokenFromPage(bag, page+1)
	if err != nil {
		return nil, nil, err
	}

	return resources, &rs.SyncOpResults{NextPageToken: nextPage}, nil
}

// Entitlements always returns an empty slice for members.
func (m *memberBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants always returns an empty slice for members since they don't have any entitlements.
func (m *memberBuilder) Grants(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func newMemberBuilder(client *cloudflare.API, accountId string) *memberBuilder {
	return &memberBuilder{
		resourceType: memberResourceType,
		client:       client,
		accountId:    accountId,
	}
}
