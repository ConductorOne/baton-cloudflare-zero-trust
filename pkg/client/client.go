// Package client calls the Cloudflare v4 API for the account this connector
// syncs. It owns authentication, paging, rate-limit annotations, and mapping
// HTTP failures to gRPC codes; it returns one page per list call.
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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultBaseURL is the Cloudflare v4 API root.
const defaultBaseURL = "https://api.cloudflare.com/client/v4"

// requestsPerSecond keeps a long sync under Cloudflare's 1200 requests per
// 5 minutes per user.
const requestsPerSecond = 4

const (
	errMissingAccountID             = "required missing account ID"
	errMissingMemberID              = "required missing member ID"
	errMissingMemberRolesOrPolicies = "account member must have either roles or policies, not both"
)

var (
	ErrMissingAccountID             = errors.New(errMissingAccountID)
	ErrMissingMemberID              = errors.New(errMissingMemberID)
	ErrMissingMemberRolesOrPolicies = errors.New(errMissingMemberRolesOrPolicies)
)

// Client calls the Cloudflare API for a single account.
type Client struct {
	http        *uhttp.BaseHttpClient
	baseURL     *url.URL
	accountID   string
	authHeaders map[string]string
}

// New returns a Client authenticated with an API token, or with an API key and
// email when no API token is set. Requests go through a uhttp client so they
// get Baton logging and gRPC-coded errors, and are throttled to 4 per second:
// Cloudflare allows 1200 requests per 5 minutes per user, and going over
// blocks every call from that user for the rest of the window, which outlasts
// the provisioning retries. baseURL overrides the Cloudflare API URL when
// non-empty.
func New(ctx context.Context, accountID, apiToken, apiKey, email, baseURL string) (*Client, error) {
	var authHeaders map[string]string
	switch {
	case apiToken != "":
		authHeaders = map[string]string{"Authorization": "Bearer " + apiToken}
	case apiKey != "" && email != "":
		authHeaders = map[string]string{"X-Auth-Key": apiKey, "X-Auth-Email": email}
	default:
		return nil, errors.New("missing credentials: set an API token, or an API key and email")
	}

	if baseURL == "" {
		baseURL = defaultBaseURL
	} else if err := validateBaseURL(baseURL); err != nil {
		return nil, err
	}
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}

	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}
	baseHTTPClient, err := uhttp.NewBaseHttpClientWithContext(ctx, httpClient, uhttp.WithRateLimiter(requestsPerSecond, time.Second))
	if err != nil {
		return nil, fmt.Errorf("create base HTTP client: %w", err)
	}

	return &Client{
		http:        baseHTTPClient,
		baseURL:     parsedBaseURL,
		accountID:   accountID,
		authHeaders: authHeaders,
	}, nil
}

// requestOptions are the optional parts of a request.
type requestOptions struct {
	query url.Values
	body  any
	// noCache bypasses uhttp's GET cache. Reads that feed a write use it, so
	// the write is never built on a stale copy.
	noCache bool
}

// doRequest calls the endpoint at the account-relative path, decodes the
// envelope's result into result (when non-nil), and returns the envelope's
// paging info. Path segments are escaped here. The returned annotations carry
// the response's rate-limit data and are set even when the call fails.
func (c *Client) doRequest(ctx context.Context, method string, path []string, opts requestOptions, result any) (*resultInfo, annotations.Annotations, error) {
	if c.accountID == "" {
		return nil, nil, ErrMissingAccountID
	}

	segments := []string{"accounts", url.PathEscape(c.accountID)}
	for _, segment := range path {
		segments = append(segments, url.PathEscape(segment))
	}
	u := c.baseURL.JoinPath(segments...)
	if opts.query != nil {
		u.RawQuery = opts.query.Encode()
	}

	reqOpts := []uhttp.RequestOption{uhttp.WithAcceptJSONHeader()}
	for key, value := range c.authHeaders {
		reqOpts = append(reqOpts, uhttp.WithHeader(key, value))
	}
	if opts.body != nil {
		reqOpts = append(reqOpts, uhttp.WithJSONBody(opts.body))
	}
	if opts.noCache {
		reqOpts = append(reqOpts, uhttp.WithNoCache())
	}

	req, err := c.http.NewRequest(ctx, method, u, reqOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}

	var (
		env  envelope
		desc *v2.RateLimitDescription
	)
	resp, err := c.http.Do(req, decodeEnvelope(&env), captureRateLimit(&desc))
	if resp != nil {
		defer resp.Body.Close()
	}
	annos := rateLimitAnnotations(desc)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests && desc != nil {
			err = withRateLimitDetails(err, desc)
		}
		return nil, annos, err
	}

	// Cloudflare reports some failures in the envelope of a 2xx response.
	if !env.Success {
		return nil, annos, status.Errorf(codes.Unknown, "cloudflare API request unsuccessful: %s", env.Message())
	}

	if result != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, result); err != nil {
			return nil, annos, fmt.Errorf("decode result: %w", err)
		}
	}

	return env.ResultInfo, annos, nil
}

// AccessKeysConfig reads the account's Access key rotation settings to verify
// the credentials and account ID. The settings themselves are not used.
// GET /accounts/{account_id}/access/keys
// Permission: Account Settings Read.
func (c *Client) AccessKeysConfig(ctx context.Context) (annotations.Annotations, error) {
	_, annos, err := c.doRequest(ctx, http.MethodGet, []string{"access", "keys"}, requestOptions{}, nil)
	if err != nil {
		return annos, fmt.Errorf("get access keys config: %w", err)
	}
	return annos, nil
}

// ListAccessUsers returns one page of Zero Trust Access users and the token
// for the next page ("" after the last page).
// GET /accounts/{account_id}/access/users
// Permission: Access: Apps and Policies Read.
func (c *Client) ListAccessUsers(ctx context.Context, pageToken string) ([]*AccessUser, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	var users []*AccessUser
	info, annos, err := c.doRequest(ctx, http.MethodGet, []string{"access", "users"}, requestOptions{query: pageQuery(page)}, &users)
	if err != nil {
		return nil, "", annos, fmt.Errorf("list access users (page %d): %w", page, err)
	}

	return users, nextPageToken(page, info, len(users)), annos, nil
}

// ListAccountMembers returns one page of account members and the token for
// the next page ("" after the last page).
// GET /accounts/{account_id}/members
// Permission: Memberships Read.
func (c *Client) ListAccountMembers(ctx context.Context, pageToken string) ([]*AccountMember, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	var members []*AccountMember
	info, annos, err := c.doRequest(ctx, http.MethodGet, []string{"members"}, requestOptions{query: pageQuery(page)}, &members)
	if err != nil {
		return nil, "", annos, fmt.Errorf("list account members (page %d): %w", page, err)
	}

	return members, nextPageToken(page, info, len(members)), annos, nil
}

// AccountMember returns an account member, bypassing the HTTP cache because
// callers modify and write the member back. An empty member ID would address
// the member collection instead of a member, so it is rejected.
// GET /accounts/{account_id}/members/{member_id}
// Permission: Memberships Read.
func (c *Client) AccountMember(ctx context.Context, memberID string) (AccountMember, annotations.Annotations, error) {
	if memberID == "" {
		return AccountMember{}, nil, ErrMissingMemberID
	}

	var member AccountMember
	_, annos, err := c.doRequest(ctx, http.MethodGet, []string{"members", memberID}, requestOptions{noCache: true}, &member)
	if err != nil {
		return AccountMember{}, annos, fmt.Errorf("get account member %s: %w", memberID, err)
	}
	return member, annos, nil
}

// UpdateAccountMember replaces an account member's roles or policies. The
// member must carry exactly one of the two.
// PUT /accounts/{account_id}/members/{member_id}
// Permission: Memberships Write.
func (c *Client) UpdateAccountMember(ctx context.Context, memberID string, member AccountMember) (AccountMember, annotations.Annotations, error) {
	if memberID == "" {
		return AccountMember{}, nil, ErrMissingMemberID
	}
	if (len(member.Roles) > 0) == (len(member.Policies) > 0) {
		return AccountMember{}, nil, ErrMissingMemberRolesOrPolicies
	}

	var updated AccountMember
	_, annos, err := c.doRequest(ctx, http.MethodPut, []string{"members", memberID}, requestOptions{body: member}, &updated)
	if err != nil {
		return AccountMember{}, annos, fmt.Errorf("update account member %s: %w", memberID, err)
	}
	return updated, annos, nil
}

// ListAccessGroups returns one page of Access groups and the token for the
// next page ("" after the last page).
// GET /accounts/{account_id}/access/groups
// Permission: Access: Organizations, Identity Providers, and Groups Read.
func (c *Client) ListAccessGroups(ctx context.Context, pageToken string) ([]*AccessGroup, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	var groups []*AccessGroup
	info, annos, err := c.doRequest(ctx, http.MethodGet, []string{"access", "groups"}, requestOptions{query: pageQuery(page)}, &groups)
	if err != nil {
		return nil, "", annos, fmt.Errorf("list access groups (page %d): %w", page, err)
	}

	return groups, nextPageToken(page, info, len(groups)), annos, nil
}

// GetAccessGroup returns one Access group, bypassing the HTTP cache because
// Grant and Revoke modify and write the group back.
// GET /accounts/{account_id}/access/groups/{group_id}
// Permission: Access: Organizations, Identity Providers, and Groups Read.
func (c *Client) GetAccessGroup(ctx context.Context, groupID string) (AccessGroup, annotations.Annotations, error) {
	var group AccessGroup
	_, annos, err := c.doRequest(ctx, http.MethodGet, []string{"access", "groups", groupID}, requestOptions{noCache: true}, &group)
	if err != nil {
		return AccessGroup{}, annos, fmt.Errorf("get access group %s: %w", groupID, err)
	}
	return group, annos, nil
}

// UpdateAccessGroupInclude replaces a group's Include list, carrying the rest
// of the group over unchanged. The endpoint replaces the whole group, so
// sending only Include would write an empty name and clear both other rule
// lists.
// PUT /accounts/{account_id}/access/groups/{group_id}
// Permission: Access: Organizations, Identity Providers, and Groups Write.
func (c *Client) UpdateAccessGroupInclude(ctx context.Context, group *AccessGroup, include []interface{}) (annotations.Annotations, error) {
	if group.ID == "" {
		return nil, errors.New("access group ID cannot be empty")
	}

	body := updateAccessGroupBody{
		ID:      group.ID,
		Name:    group.Name,
		Include: include,
		Require: group.Require,
		Exclude: group.Exclude,
	}
	_, annos, err := c.doRequest(ctx, http.MethodPut, []string{"access", "groups", group.ID}, requestOptions{body: body}, nil)
	if err != nil {
		return annos, fmt.Errorf("update access group %s: %w", group.ID, err)
	}
	return annos, nil
}

// ListAccountRoles returns one page of account roles and the token for the
// next page ("" after the last page).
// GET /accounts/{account_id}/roles
// Permission: Memberships Read.
func (c *Client) ListAccountRoles(ctx context.Context, pageToken string) ([]*AccountRole, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	var roles []*AccountRole
	info, annos, err := c.doRequest(ctx, http.MethodGet, []string{"roles"}, requestOptions{query: pageQuery(page)}, &roles)
	if err != nil {
		return nil, "", annos, fmt.Errorf("list account roles (page %d): %w", page, err)
	}

	return roles, nextPageToken(page, info, len(roles)), annos, nil
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
func (c *Client) RolePermissionGroup(ctx context.Context, roleID string) (PermissionGroup, annotations.Annotations, error) {
	var role AccountRole
	_, annos, err := c.doRequest(ctx, http.MethodGet, []string{"roles", roleID}, requestOptions{}, &role)
	if err != nil {
		return PermissionGroup{}, annos, fmt.Errorf("get role %s: %w", roleID, err)
	}

	query := url.Values{
		"depth": []string{"2"},
		"name":  []string{role.Name},
	}
	var groups []PermissionGroup
	_, annos, err = c.doRequest(ctx, http.MethodGet, []string{"iam", "permission_groups"}, requestOptions{query: query}, &groups)
	if err != nil {
		return PermissionGroup{}, annos, fmt.Errorf("list permission groups for role %q: %w", role.Name, err)
	}
	if len(groups) == 0 {
		return PermissionGroup{}, annos, fmt.Errorf("no permission group found for role %q", role.Name)
	}

	return groups[0], annos, nil
}
