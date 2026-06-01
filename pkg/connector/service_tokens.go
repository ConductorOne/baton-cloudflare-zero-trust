package connector

import (
	"context"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// serviceTokenSecretDetail is the §2.8 axis-2 detail string for ZT Access service tokens.
const serviceTokenSecretDetail = "cloudflare.zt.service_token" //nolint:gosec // axis-2 detail label, not a credential value

type serviceTokenBuilder struct {
	resourceType *v2.ResourceType
	client       *cloudflare.API
	accountId    string
}

func (s *serviceTokenBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return s.resourceType
}

// serviceTokenResource models a Zero Trust Access service token as a SECRET resource.
// Service tokens are pure machine credentials (Client ID + Client Secret); the secret
// value is only returned at creation, never on list, so no secret material is carried.
func serviceTokenResource(token cloudflare.AccessServiceToken) (*v2.Resource, error) {
	secretTraitOpts := []rs.SecretTraitOption{
		rs.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		rs.WithSecretDetail(serviceTokenSecretDetail),
	}
	if token.CreatedAt != nil {
		secretTraitOpts = append(secretTraitOpts, rs.WithSecretCreatedAt(*token.CreatedAt))
	}
	if token.ExpiresAt != nil {
		secretTraitOpts = append(secretTraitOpts, rs.WithSecretExpiresAt(*token.ExpiresAt))
	}

	displayName := token.Name
	if displayName == "" {
		displayName = token.ID
	}

	return rs.NewSecretResource(displayName, serviceTokenResourceType, token.ID, secretTraitOpts)
}

// List returns the account's Zero Trust Access service tokens. cloudflare-go's
// ListAccessServiceTokens returns the full set in a single call, so there is no
// page token to thread.
func (s *serviceTokenBuilder) List(ctx context.Context, _ *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if s.accountId == "" {
		return nil, "", nil, ErrMissingAccountID
	}

	tokens, _, err := s.client.ListAccessServiceTokens(ctx, cloudflare.AccountIdentifier(s.accountId), cloudflare.ListAccessServiceTokensParams{})
	if err != nil {
		return nil, "", nil, wrapError(err, "failed to list access service tokens")
	}

	resources := make([]*v2.Resource, 0, len(tokens))
	for _, token := range tokens {
		resource, err := serviceTokenResource(token)
		if err != nil {
			return nil, "", nil, wrapError(err, "failed to create service token resource")
		}
		resources = append(resources, resource)
	}

	return resources, "", nil, nil
}

func (s *serviceTokenBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (s *serviceTokenBuilder) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newServiceTokenBuilder(client *cloudflare.API, accountId string) *serviceTokenBuilder {
	return &serviceTokenBuilder{
		resourceType: serviceTokenResourceType,
		client:       client,
		accountId:    accountId,
	}
}
