package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// serviceTokenSecretDetail identifies the credential kind on the secret trait.
const serviceTokenSecretDetail = "cloudflare.zt.service_token" //nolint:gosec // credential-kind label, not a credential value

type serviceTokenBuilder struct {
	resourceType *v2.ResourceType
	client       *cloudflare.API
	accountId    string
}

func (s *serviceTokenBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return s.resourceType
}

// serviceTokenResource models a Zero Trust Access service token as a secret
// resource. The client secret is only returned when a token is created, never
// on list, so no secret material is carried.
func serviceTokenResource(token cloudflare.AccessServiceToken, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	secretTraitOpts := []rs.SecretTraitOption{
		rs.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		rs.WithSecretDetail(serviceTokenSecretDetail),
	}
	if token.ExpiresAt != nil {
		secretTraitOpts = append(secretTraitOpts, rs.WithSecretExpiresAt(*token.ExpiresAt))
	}

	displayName := token.Name
	if displayName == "" {
		displayName = token.ID
	}

	profile := map[string]interface{}{
		"client_id": token.ClientID,
	}
	if token.Duration != "" {
		profile["duration"] = token.Duration
	}

	resourceOpts := []rs.ResourceOption{
		rs.WithParentResourceID(parentResourceID),
		rs.WithResourceProfile(profile),
	}
	if token.CreatedAt != nil {
		resourceOpts = append(resourceOpts, rs.WithResourceCreatedAt(*token.CreatedAt))
	}

	return rs.NewSecretResource(
		displayName,
		serviceTokenResourceType,
		token.ID,
		secretTraitOpts,
		resourceOpts...,
	)
}

// listServiceTokensPage fetches one page of service tokens. cloudflare-go's
// ListAccessServiceTokens sends no paging parameters and so only ever returns
// the API's first page; the endpoint does accept page/per_page, so the request
// is made directly to page through every token.
func (s *serviceTokenBuilder) listServiceTokensPage(ctx context.Context, page int) ([]cloudflare.AccessServiceToken, cloudflare.ResultInfo, error) {
	query := url.Values{}
	query.Set("page", strconv.Itoa(page))
	query.Set("per_page", strconv.Itoa(resourcePageSize))
	endpoint := fmt.Sprintf("/accounts/%s/access/service_tokens?%s", s.accountId, query.Encode())

	res, err := s.client.Raw(ctx, http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return nil, cloudflare.ResultInfo{}, err
	}

	var tokens []cloudflare.AccessServiceToken
	if err := json.Unmarshal(res.Result, &tokens); err != nil {
		return nil, cloudflare.ResultInfo{}, err
	}

	var info cloudflare.ResultInfo
	if res.ResultInfo != nil {
		info = *res.ResultInfo
	}

	return tokens, info, nil
}

// hasMoreServiceTokenPages reports whether another page follows the given one.
// The page count comes from total_pages, or from total_count and per_page when
// total_pages is absent, the same fallback cloudflare-go's own pagination uses.
// A full page with no usable paging metadata is an error rather than the last
// page, so a sync can never silently stop short.
func hasMoreServiceTokenPages(info cloudflare.ResultInfo, page int, received int) (bool, error) {
	totalPages := info.TotalPages
	if totalPages == 0 && info.Total > 0 && info.PerPage > 0 {
		totalPages = (info.Total + info.PerPage - 1) / info.PerPage
	}
	if totalPages > 0 {
		return page < totalPages, nil
	}
	if received < resourcePageSize {
		return false, nil
	}
	return false, fmt.Errorf("baton-cloudflare-zero-trust: service tokens page %d returned a full page without pagination info", page)
}

// List returns the account's Zero Trust Access service tokens, one page per call.
func (s *serviceTokenBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	if s.accountId == "" {
		return nil, nil, ErrMissingAccountID
	}

	page, err := getPageFromPageToken(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}
	if page == 0 {
		page = 1
	}

	tokens, info, err := s.listServiceTokensPage(ctx, page)
	if err != nil {
		return nil, nil, wrapError(err, "failed to list access service tokens")
	}

	resources := make([]*v2.Resource, 0, len(tokens))
	for _, token := range tokens {
		resource, err := serviceTokenResource(token, parentResourceID)
		if err != nil {
			return nil, nil, wrapError(err, "failed to create service token resource")
		}
		resources = append(resources, resource)
	}

	more, err := hasMoreServiceTokenPages(info, page, len(tokens))
	if err != nil {
		return nil, nil, err
	}
	if !more {
		return resources, nil, nil
	}

	return resources, &rs.SyncOpResults{NextPageToken: strconv.Itoa(page + 1)}, nil
}

// Entitlements returns nil. The service token resource type is annotated with
// SkipEntitlementsAndGrants, so the SDK never invokes this per-resource hook.
func (s *serviceTokenBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns nil. The service token resource type is annotated with
// SkipEntitlementsAndGrants, so the SDK never invokes this per-resource hook.
func (s *serviceTokenBuilder) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func newServiceTokenBuilder(client *cloudflare.API, accountId string) *serviceTokenBuilder {
	return &serviceTokenBuilder{
		resourceType: serviceTokenResourceType,
		client:       client,
		accountId:    accountId,
	}
}
