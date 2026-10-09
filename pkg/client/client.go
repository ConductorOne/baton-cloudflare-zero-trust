package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
)

const (
	errMissingAccountID = "required missing account ID"
	errMissingMemberID  = "required missing member ID"
)

var (
	ErrMissingAccountID = errors.New(errMissingAccountID)
	ErrMissingMemberID  = errors.New(errMissingMemberID)
)

// Client wraps the cloudflare-go API client for a single Cloudflare account.
type Client struct {
	api       *cloudflare.API
	accountID string
}

// New returns a Client authenticated with an API token, or with an API key and
// email when no API token is set. baseURL overrides the Cloudflare API URL
// when non-empty.
func New(accountID, apiToken, apiKey, email, baseURL string) (*Client, error) {
	var (
		api *cloudflare.API
		err error
	)

	var opts []cloudflare.Option
	if baseURL != "" {
		opts = append(opts, cloudflare.BaseURL(baseURL))
	}

	if apiKey != "" && email != "" {
		api, err = cloudflare.New(apiKey, email, opts...)
		if err != nil {
			return nil, err
		}
	}

	if apiToken != "" {
		api, err = cloudflare.NewWithAPIToken(apiToken, opts...)
		if err != nil {
			return nil, err
		}
	}

	return &Client{
		api:       api,
		accountID: accountID,
	}, nil
}

func (c *Client) AccessKeysConfig(ctx context.Context) (cloudflare.AccessKeysConfig, error) {
	return c.api.AccessKeysConfig(ctx, c.accountID)
}

func (c *Client) ListAccessUsers(ctx context.Context, params cloudflare.AccessUserParams) ([]cloudflare.AccessUser, *cloudflare.ResultInfo, error) {
	return c.api.ListAccessUsers(ctx, cloudflare.AccountIdentifier(c.accountID), params)
}

func (c *Client) AccountMembers(ctx context.Context, pageOpts cloudflare.PaginationOptions) ([]cloudflare.AccountMember, cloudflare.ResultInfo, error) {
	return c.api.AccountMembers(ctx, c.accountID, pageOpts)
}

// AccountMember returns an account member. cloudflare-go's AccountMember
// authenticates with whichever scheme the client was built for and turns a
// non-2xx response into a typed *cloudflare.Error, so neither concern is
// handled here. It does not reject an empty member ID, which would address the
// member collection instead of a member, so that is guarded.
func (c *Client) AccountMember(ctx context.Context, memberID string) (cloudflare.AccountMember, error) {
	if c.accountID == "" {
		return cloudflare.AccountMember{}, ErrMissingAccountID
	}
	if memberID == "" {
		return cloudflare.AccountMember{}, ErrMissingMemberID
	}

	return c.api.AccountMember(ctx, c.accountID, memberID)
}

func (c *Client) UpdateAccountMember(ctx context.Context, memberID string, member cloudflare.AccountMember) (cloudflare.AccountMember, error) {
	return c.api.UpdateAccountMember(ctx, c.accountID, memberID, member)
}

// FindMemberByUserID pages through the account's members looking for the one
// whose native user ID matches userId. There is no way to filter members by
// user ID server-side, so this always scans until a match or the last page.
// A nil member with a nil error means no account member has this user ID —
// e.g. the ID belongs to a pure Access user with no account membership.
func (c *Client) FindMemberByUserID(ctx context.Context, userId string, perPage int) (*cloudflare.AccountMember, error) {
	page := 1
	for {
		members, info, err := c.AccountMembers(ctx, cloudflare.PaginationOptions{
			Page:    page,
			PerPage: perPage,
		})
		if err != nil {
			return nil, err
		}

		for i := range members {
			if members[i].User.ID == userId {
				return &members[i], nil
			}
		}

		if info.TotalPages <= info.Page {
			return nil, nil
		}
		page++
	}
}

func (c *Client) ListAccessGroups(ctx context.Context) ([]cloudflare.AccessGroup, *cloudflare.ResultInfo, error) {
	return c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
}

func (c *Client) GetAccessGroup(ctx context.Context, groupID string) (cloudflare.AccessGroup, error) {
	return c.api.GetAccessGroup(ctx, cloudflare.AccountIdentifier(c.accountID), groupID)
}

// UpdateAccessGroupInclude replaces a group's Include list, carrying the rest
// of the group over unchanged. UpdateAccessGroupParams serializes Name,
// Require and Exclude without omitempty, so sending only Include would write
// an empty name and clear both other rule lists.
func (c *Client) UpdateAccessGroupInclude(ctx context.Context, group *cloudflare.AccessGroup, include []interface{}) error {
	_, err := c.api.UpdateAccessGroup(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.UpdateAccessGroupParams{
		ID:      group.ID,
		Name:    group.Name,
		Include: include,
		Require: group.Require,
		Exclude: group.Exclude,
	})
	return err
}

// ListAccountRoles returns every role in the account.
//
// ListAccountRoles only returns a ResultInfo (and thus a way to detect more
// pages) when called without explicit Page/PerPage; passing those turns off
// the client's own pagination and leaves no signal that more roles exist. So
// this is called with no paging params, letting the client fetch every role
// internally in a single call, the same way ListAccessGroups is called.
func (c *Client) ListAccountRoles(ctx context.Context) ([]cloudflare.AccountRole, error) {
	return c.api.ListAccountRoles(ctx, &cloudflare.ResourceContainer{Identifier: c.accountID}, cloudflare.ListAccountRolesParams{})
}

// RolePermissionGroup finds the permission group that mirrors the given
// classic role. Accounts enrolled in Domain Scoped Roles represent grants via
// Policies (a permission group + resource group pair), not the legacy Roles
// list, and reject an update that sets Roles on a member that already has
// Policies. Permission groups share their name with the role they mirror, so
// the role's name is used to find the equivalent group.
func (c *Client) RolePermissionGroup(ctx context.Context, roleID string) (cloudflare.PermissionGroup, error) {
	role, err := c.api.GetAccountRole(ctx, cloudflare.AccountIdentifier(c.accountID), roleID)
	if err != nil {
		return cloudflare.PermissionGroup{}, fmt.Errorf("cloudflare-zero-trust-connector: failed to get role: %w", err)
	}

	groups, err := c.api.ListPermissionGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListPermissionGroupParams{RoleName: role.Name})
	if err != nil {
		return cloudflare.PermissionGroup{}, fmt.Errorf("cloudflare-zero-trust-connector: failed to list permission groups: %w", err)
	}
	if len(groups) == 0 {
		return cloudflare.PermissionGroup{}, fmt.Errorf("baton-cloudflare-zero-trust: no permission group found for role %q", role.Name)
	}

	return groups[0], nil
}
