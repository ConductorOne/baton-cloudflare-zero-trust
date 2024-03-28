package connector

import (
	"context"
	"time"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/helpers"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	client       *cloudflare.API
	accountId    string
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

func newUserResource(user cloudflare.AccessUser) (*v2.Resource, error) {
	firstName, lastName := helpers.SplitFullName(user.Name)
	profile := map[string]interface{}{
		"login":       user.Email,
		"first_name":  firstName,
		"last_name":   lastName,
		"email":       user.Email,
		"access_seat": *user.AccessSeat,
	}

	userTraits := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED),
		rs.WithUserLogin(user.Email),
		rs.WithEmail(user.Email, true),
	}

	if user.LastSuccessfulLogin != "" {
		loginTime, err := time.Parse("2006-01-02T15:04:05Z", user.LastSuccessfulLogin)
		if err == nil {
			userTraits = append(userTraits, rs.WithLastLogin(loginTime))
		}
	}

	if user.CreatedAt != "" {
		createdAt, err := time.Parse("2006-01-02T15:04:05.000000Z", user.CreatedAt)
		if err == nil {
			userTraits = append(userTraits, rs.WithCreatedAt(createdAt))
		}
	}

	displayName := user.Name
	if firstName == "" {
		displayName = user.Email
	}

	resource, err := rs.NewUserResource(displayName, userResourceType, user.ID, userTraits)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: o.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	users, info, err := o.client.ListAccessUsers(ctx, cloudflare.AccountIdentifier(o.accountId), cloudflare.AccessUserParams{
		ResultInfo: cloudflare.ResultInfo{
			Page:    page,
			PerPage: resourcePageSize,
		},
	})
	if err != nil {
		return nil, "", nil, wrapError(err, "failed to list users")
	}

	resources := make([]*v2.Resource, 0, len(users))
	for _, user := range users {
		resource, err := newUserResource(user)
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
func (o *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newUserBuilder(client *cloudflare.API, accountId string) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       client,
		accountId:    accountId,
	}
}
