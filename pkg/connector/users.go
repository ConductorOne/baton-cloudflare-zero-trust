package connector

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// User resources are sourced from two Cloudflare APIs. Both are paginated
// independently within a single bag so that a sync fetches every user.
const (
	accessUsersPageState    = "access_users"
	accountMembersPageState = "account_members"
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
	firstName, lastName := rs.SplitFullName(user.Name)
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

// newUserResourceFromMember builds a user resource from an account member so
// that account members and Access users are emitted as a single resource type.
func newUserResourceFromMember(member cloudflare.AccountMember) (*v2.Resource, error) {
	accessSeat := false
	accUser := cloudflare.AccessUser{
		ID:         member.User.ID,
		Name:       fmt.Sprintf("%s %s", member.User.FirstName, member.User.LastName),
		Email:      member.User.Email,
		AccessSeat: &accessSeat,
	}

	return newUserResource(accUser)
}

// List returns all the users from both the Access users and account members
// endpoints as user resource objects. Both endpoints are paginated within a
// single bag: the Access users pages are exhausted first, then the account
// members pages, so every user is shipped in one resource type.
func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		// Stack is LIFO: account members are processed after Access users.
		bag.Push(pagination.PageState{ResourceTypeID: accountMembersPageState})
		bag.Push(pagination.PageState{ResourceTypeID: accessUsersPageState})
	}

	page, err := getPageFromPageToken(bag.PageToken())
	if err != nil {
		return nil, nil, err
	}
	if page == 0 {
		page = 1
	}

	var (
		resources   []*v2.Resource
		currentPage int
		totalPages  int
	)

	switch bag.ResourceTypeID() {
	case accessUsersPageState:
		users, info, err := o.client.ListAccessUsers(ctx, cloudflare.AccountIdentifier(o.accountId), cloudflare.AccessUserParams{
			ResultInfo: cloudflare.ResultInfo{
				Page:    page,
				PerPage: resourcePageSize,
			},
		})
		if err != nil {
			return nil, nil, wrapError(err, "failed to list users")
		}

		resources = make([]*v2.Resource, 0, len(users))
		for _, user := range users {
			resource, err := newUserResource(user)
			if err != nil {
				return nil, nil, wrapError(err, "failed to create user resource")
			}

			resources = append(resources, resource)
		}
		currentPage, totalPages = info.Page, info.TotalPages

	case accountMembersPageState:
		members, info, err := o.client.AccountMembers(ctx, o.accountId, cloudflare.PaginationOptions{
			Page:    page,
			PerPage: resourcePageSize,
		})
		if err != nil {
			return nil, nil, wrapError(err, "failed to list members")
		}

		resources = make([]*v2.Resource, 0, len(members))
		for _, member := range members {
			resource, err := newUserResourceFromMember(member)
			if err != nil {
				return nil, nil, wrapError(err, "failed to create user resource")
			}

			resources = append(resources, resource)
		}
		currentPage, totalPages = info.Page, info.TotalPages

	default:
		return nil, nil, fmt.Errorf("baton-cloudflare-zero-trust: unexpected page state %q", bag.ResourceTypeID())
	}

	// If the current endpoint has more pages, advance its page number.
	// Otherwise pop it from the bag and continue with the next endpoint (if any).
	var nextToken string
	if currentPage < totalPages {
		nextToken, err = bag.NextToken(strconv.Itoa(page + 1))
	} else {
		nextToken, err = bag.NextToken("")
	}
	if err != nil {
		return nil, nil, err
	}

	if nextToken == "" {
		return resources, nil, nil
	}

	return resources, &rs.SyncOpResults{NextPageToken: nextToken}, nil
}

// Entitlements always returns an empty slice for users.
func (o *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *userBuilder) Grants(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func newUserBuilder(client *cloudflare.API, accountId string) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       client,
		accountId:    accountId,
	}
}
