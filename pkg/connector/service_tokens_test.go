package connector

import (
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceTokenResource(t *testing.T) {
	created := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	expires := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
	token := cloudflare.AccessServiceToken{
		ID:        "11111111-2222-3333-4444-555555555555",
		Name:      "ci-runner",
		ClientID:  "abc123.access",
		CreatedAt: &created,
		ExpiresAt: &expires,
	}

	resource, err := serviceTokenResource(token)
	require.NoError(t, err)
	assert.Equal(t, token.ID, resource.GetId().GetResource())
	assert.Equal(t, serviceTokenResourceType.GetId(), resource.GetId().GetResourceType())
	assert.Equal(t, token.Name, resource.GetDisplayName())

	secretTrait := &v2.SecretTrait{}
	annos := annotations.Annotations(resource.GetAnnotations())
	ok, err := annos.Pick(secretTrait)
	require.NoError(t, err)
	require.True(t, ok, "expected a SecretTrait on the service_token resource")

	assert.Equal(t, v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET, secretTrait.GetCredentialType())
	assert.Equal(t, serviceTokenSecretDetail, secretTrait.GetCredentialDetail())
	assert.Equal(t, created, secretTrait.GetCreatedAt().AsTime())
	assert.Equal(t, expires, secretTrait.GetExpiresAt().AsTime())
}

func TestServiceTokenResourceFallbackDisplayName(t *testing.T) {
	token := cloudflare.AccessServiceToken{ID: "no-name-token"}

	resource, err := serviceTokenResource(token)
	require.NoError(t, err)
	assert.Equal(t, token.ID, resource.GetDisplayName())
}
