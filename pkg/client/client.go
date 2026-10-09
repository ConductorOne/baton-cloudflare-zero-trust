// Package client wraps the cloudflare-go SDK for the Cloudflare account this
// connector syncs. cloudflare-go builds every request URL itself; this package
// owns authentication, paging, rate-limit annotations, and error mapping.
//
// Endpoints used (all under https://api.cloudflare.com/client/v4, API docs at
// https://developers.cloudflare.com/api/):
//
//	GET  /accounts/{account_id}/access/keys
//	GET  /accounts/{account_id}/access/users
//	GET  /accounts/{account_id}/access/groups
//	GET  /accounts/{account_id}/access/groups/{group_id}
//	PUT  /accounts/{account_id}/access/groups/{group_id}
//	GET  /accounts/{account_id}/members
//	GET  /accounts/{account_id}/members/{member_id}
//	PUT  /accounts/{account_id}/members/{member_id}
//	GET  /accounts/{account_id}/roles
//	GET  /accounts/{account_id}/roles/{role_id}
//	GET  /accounts/{account_id}/iam/permission_groups
//
// Permission names below are the Cloudflare API token permission groups this
// connector declares for the resource type that makes the call.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/cloudflare/cloudflare-go"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
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
// email when no API token is set. Requests go through a uhttp client so they
// get Baton logging, and rate-limit headers are captured for annotations.
// baseURL overrides the Cloudflare API URL when non-empty.
func New(ctx context.Context, accountID, apiToken, apiKey, email, baseURL string) (*Client, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}
	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	httpClient.Transport = &rateLimitTransport{base: transport}

	opts := []cloudflare.Option{cloudflare.HTTPClient(httpClient)}
	if baseURL != "" {
		if err := validateBaseURL(baseURL); err != nil {
			return nil, err
		}
		opts = append(opts, cloudflare.BaseURL(baseURL))
	}

	var api *cloudflare.API
	switch {
	case apiToken != "":
		api, err = cloudflare.NewWithAPIToken(apiToken, opts...)
	case apiKey != "" && email != "":
		api, err = cloudflare.New(apiKey, email, opts...)
	default:
		return nil, errors.New("missing credentials: set an API token, or an API key and email")
	}
	if err != nil {
		return nil, fmt.Errorf("create Cloudflare API client: %w", err)
	}

	return &Client{
		api:       api,
		accountID: accountID,
	}, nil
}

// AccessKeysConfig returns the account's Access key rotation settings. It is
// used to verify the credentials and account ID.
// GET /accounts/{account_id}/access/keys
// Permission: Account Settings Read.
func (c *Client) AccessKeysConfig(ctx context.Context) (cloudflare.AccessKeysConfig, annotations.Annotations, error) {
	ctx, capture := withRateLimitCapture(ctx)
	cfg, err := c.api.AccessKeysConfig(ctx, c.accountID)
	if err != nil {
		return cloudflare.AccessKeysConfig{}, capture.annotations(), fmt.Errorf("get access keys config: %w", mapCloudflareError(err))
	}
	return cfg, capture.annotations(), nil
}

// ListAccessUsers returns one page of Zero Trust Access users and the token
// for the next page ("" after the last page).
// GET /accounts/{account_id}/access/users
// Permission: Access: Apps and Policies Read.
func (c *Client) ListAccessUsers(ctx context.Context, pageToken string) ([]*cloudflare.AccessUser, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	ctx, capture := withRateLimitCapture(ctx)
	users, info, err := c.api.ListAccessUsers(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.AccessUserParams{
		ResultInfo: cloudflare.ResultInfo{
			Page:    page,
			PerPage: PageSize,
		},
	})
	if err != nil {
		return nil, "", capture.annotations(), fmt.Errorf("list access users (page %d): %w", page, mapCloudflareError(err))
	}

	return toPointers(users), nextPageToken(page, info, len(users)), capture.annotations(), nil
}

// ListAccountMembers returns one page of account members and the token for
// the next page ("" after the last page).
// GET /accounts/{account_id}/members
// Permission: Memberships Read.
func (c *Client) ListAccountMembers(ctx context.Context, pageToken string) ([]*cloudflare.AccountMember, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	ctx, capture := withRateLimitCapture(ctx)
	members, info, err := c.api.AccountMembers(ctx, c.accountID, cloudflare.PaginationOptions{
		Page:    page,
		PerPage: PageSize,
	})
	if err != nil {
		return nil, "", capture.annotations(), fmt.Errorf("list account members (page %d): %w", page, mapCloudflareError(err))
	}

	return toPointers(members), nextPageToken(page, &info, len(members)), capture.annotations(), nil
}

// AccountMember returns an account member. cloudflare-go's AccountMember
// authenticates with whichever scheme the client was built for and turns a
// non-2xx response into a typed *cloudflare.Error, so neither concern is
// handled here. It does not reject an empty member ID, which would address the
// member collection instead of a member, so that is guarded.
// GET /accounts/{account_id}/members/{member_id}
// Permission: Memberships Read.
func (c *Client) AccountMember(ctx context.Context, memberID string) (cloudflare.AccountMember, annotations.Annotations, error) {
	if c.accountID == "" {
		return cloudflare.AccountMember{}, nil, ErrMissingAccountID
	}
	if memberID == "" {
		return cloudflare.AccountMember{}, nil, ErrMissingMemberID
	}

	ctx, capture := withRateLimitCapture(ctx)
	member, err := c.api.AccountMember(ctx, c.accountID, memberID)
	if err != nil {
		return cloudflare.AccountMember{}, capture.annotations(), fmt.Errorf("get account member %s: %w", memberID, mapCloudflareError(err))
	}
	return member, capture.annotations(), nil
}

// UpdateAccountMember replaces an account member's roles or policies.
// PUT /accounts/{account_id}/members/{member_id}
// Permission: Memberships Write.
func (c *Client) UpdateAccountMember(ctx context.Context, memberID string, member cloudflare.AccountMember) (cloudflare.AccountMember, annotations.Annotations, error) {
	ctx, capture := withRateLimitCapture(ctx)
	updated, err := c.api.UpdateAccountMember(ctx, c.accountID, memberID, member)
	if err != nil {
		return cloudflare.AccountMember{}, capture.annotations(), fmt.Errorf("update account member %s: %w", memberID, mapCloudflareError(err))
	}
	return updated, capture.annotations(), nil
}

// ListAccessGroups returns every Access group in the account. Called without
// paging params, cloudflare-go fetches all pages internally and returns them in
// a single result, so there is no page token.
// GET /accounts/{account_id}/access/groups
// Permission: Access: Organizations, Identity Providers, and Groups Read.
func (c *Client) ListAccessGroups(ctx context.Context) ([]*cloudflare.AccessGroup, annotations.Annotations, error) {
	ctx, capture := withRateLimitCapture(ctx)
	groups, _, err := c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
	if err != nil {
		return nil, capture.annotations(), fmt.Errorf("list access groups: %w", mapCloudflareError(err))
	}
	return toPointers(groups), capture.annotations(), nil
}

// GetAccessGroup returns one Access group.
// GET /accounts/{account_id}/access/groups/{group_id}
// Permission: Access: Organizations, Identity Providers, and Groups Read.
func (c *Client) GetAccessGroup(ctx context.Context, groupID string) (cloudflare.AccessGroup, annotations.Annotations, error) {
	ctx, capture := withRateLimitCapture(ctx)
	group, err := c.api.GetAccessGroup(ctx, cloudflare.AccountIdentifier(c.accountID), groupID)
	if err != nil {
		return cloudflare.AccessGroup{}, capture.annotations(), fmt.Errorf("get access group %s: %w", groupID, mapCloudflareError(err))
	}
	return group, capture.annotations(), nil
}

// UpdateAccessGroupInclude replaces a group's Include list, carrying the rest
// of the group over unchanged. UpdateAccessGroupParams serializes Name,
// Require and Exclude without omitempty, so sending only Include would write
// an empty name and clear both other rule lists.
// PUT /accounts/{account_id}/access/groups/{group_id}
// Permission: Access: Organizations, Identity Providers, and Groups Write.
func (c *Client) UpdateAccessGroupInclude(ctx context.Context, group *cloudflare.AccessGroup, include []interface{}) (annotations.Annotations, error) {
	ctx, capture := withRateLimitCapture(ctx)
	_, err := c.api.UpdateAccessGroup(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.UpdateAccessGroupParams{
		ID:      group.ID,
		Name:    group.Name,
		Include: include,
		Require: group.Require,
		Exclude: group.Exclude,
	})
	if err != nil {
		return capture.annotations(), fmt.Errorf("update access group %s: %w", group.ID, mapCloudflareError(err))
	}
	return capture.annotations(), nil
}

// ListAccountRoles returns every role in the account, so there is no page
// token.
//
// ListAccountRoles only returns a ResultInfo (and thus a way to detect more
// pages) when called without explicit Page/PerPage; passing those turns off
// the client's own pagination and leaves no signal that more roles exist. So
// this is called with no paging params, letting the client fetch every role
// internally in a single call, the same way ListAccessGroups is called.
// GET /accounts/{account_id}/roles
// Permission: Memberships Read.
func (c *Client) ListAccountRoles(ctx context.Context) ([]*cloudflare.AccountRole, annotations.Annotations, error) {
	ctx, capture := withRateLimitCapture(ctx)
	roles, err := c.api.ListAccountRoles(ctx, &cloudflare.ResourceContainer{Identifier: c.accountID}, cloudflare.ListAccountRolesParams{})
	if err != nil {
		return nil, capture.annotations(), fmt.Errorf("list account roles: %w", mapCloudflareError(err))
	}
	return toPointers(roles), capture.annotations(), nil
}

// RolePermissionGroup finds the permission group that mirrors the given
// classic role. Accounts enrolled in Domain Scoped Roles represent grants via
// Policies (a permission group + resource group pair), not the legacy Roles
// list, and reject an update that sets Roles on a member that already has
// Policies. Permission groups share their name with the role they mirror, so
// the role's name is used to find the equivalent group.
// GET /accounts/{account_id}/roles/{role_id}
// GET /accounts/{account_id}/iam/permission_groups?name={role_name}
// Permission: Memberships Read.
func (c *Client) RolePermissionGroup(ctx context.Context, roleID string) (cloudflare.PermissionGroup, annotations.Annotations, error) {
	ctx, capture := withRateLimitCapture(ctx)
	role, err := c.api.GetAccountRole(ctx, cloudflare.AccountIdentifier(c.accountID), roleID)
	if err != nil {
		return cloudflare.PermissionGroup{}, capture.annotations(), fmt.Errorf("get role %s: %w", roleID, mapCloudflareError(err))
	}

	groups, err := c.api.ListPermissionGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListPermissionGroupParams{RoleName: role.Name})
	if err != nil {
		return cloudflare.PermissionGroup{}, capture.annotations(), fmt.Errorf("list permission groups for role %q: %w", role.Name, mapCloudflareError(err))
	}
	if len(groups) == 0 {
		return cloudflare.PermissionGroup{}, capture.annotations(), fmt.Errorf("no permission group found for role %q", role.Name)
	}

	return groups[0], capture.annotations(), nil
}

// toPointers returns a slice of pointers to the elements of items.
func toPointers[T any](items []T) []*T {
	out := make([]*T, len(items))
	for i := range items {
		out[i] = &items[i]
	}
	return out
}
