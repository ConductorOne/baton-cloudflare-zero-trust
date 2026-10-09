package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
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
		Duration:  "8760h",
	}

	resource, err := serviceTokenResource(token, nil)
	require.NoError(t, err)
	assert.Equal(t, token.ID, resource.GetId().GetResource())
	assert.Equal(t, serviceTokenResourceType.GetId(), resource.GetId().GetResourceType())
	assert.Equal(t, token.Name, resource.GetDisplayName())
	assert.Equal(t, created, resource.GetCreatedAt().AsTime())

	secretTrait := &v2.SecretTrait{}
	annos := annotations.Annotations(resource.GetAnnotations())
	ok, err := annos.Pick(secretTrait)
	require.NoError(t, err)
	require.True(t, ok, "expected a SecretTrait on the service_token resource")

	assert.Equal(t, v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET, secretTrait.GetCredentialType())
	assert.Equal(t, serviceTokenSecretDetail, secretTrait.GetCredentialDetail())
	assert.Equal(t, expires, secretTrait.GetExpiresAt().AsTime())

	clientID, ok := rs.GetProfileStringValue(rs.GetProfile(resource), "client_id")
	require.True(t, ok)
	assert.Equal(t, token.ClientID, clientID)
	duration, ok := rs.GetProfileStringValue(rs.GetProfile(resource), "duration")
	require.True(t, ok)
	assert.Equal(t, token.Duration, duration)
}

func TestServiceTokenResourceFallbackDisplayName(t *testing.T) {
	token := cloudflare.AccessServiceToken{ID: "no-name-token"}

	resource, err := serviceTokenResource(token, nil)
	require.NoError(t, err)
	assert.Equal(t, token.ID, resource.GetDisplayName())
}

// TestServiceTokenListPaginates serves three pages of service tokens and
// checks that List requests each page in turn and stops after the last one.
func TestServiceTokenListPaginates(t *testing.T) {
	const (
		accountID  = "test-account"
		totalPages = 3
	)
	var requestedPages []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, fmt.Sprintf("/accounts/%s/access/service_tokens", accountID), r.URL.Path)
		require.Equal(t, strconv.Itoa(resourcePageSize), r.URL.Query().Get("per_page"))

		pageParam := r.URL.Query().Get("page")
		requestedPages = append(requestedPages, pageParam)
		page, err := strconv.Atoi(pageParam)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"errors":   []interface{}{},
			"messages": []interface{}{},
			"result": []map[string]interface{}{
				{"id": fmt.Sprintf("token-%d", page), "name": fmt.Sprintf("Token %d", page), "client_id": "client.access"},
			},
			"result_info": map[string]interface{}{
				"page":        page,
				"per_page":    resourcePageSize,
				"count":       1,
				"total_count": totalPages,
				"total_pages": totalPages,
			},
		}))
	}))
	defer server.Close()

	client, err := cloudflare.NewWithAPIToken("test-token", cloudflare.BaseURL(server.URL))
	require.NoError(t, err)
	builder := newServiceTokenBuilder(client, accountID)

	var (
		ids   []string
		token string
	)
	for range totalPages + 1 {
		resources, results, err := builder.List(context.Background(), nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		for _, r := range resources {
			ids = append(ids, r.GetId().GetResource())
		}
		if results == nil || results.NextPageToken == "" {
			token = ""
			break
		}
		token = results.NextPageToken
	}

	assert.Empty(t, token, "List did not terminate after the last page")
	assert.Equal(t, []string{"1", "2", "3"}, requestedPages)
	assert.Equal(t, []string{"token-1", "token-2", "token-3"}, ids)
}

// TestServiceTokenListSkipsWhenForbidden checks that an API token without
// the service tokens permission does not fail the sync.
func TestServiceTokenListSkipsWhenForbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"messages":[],"result":null}`))
	}))
	defer server.Close()

	client, err := cloudflare.NewWithAPIToken("test-token", cloudflare.BaseURL(server.URL))
	require.NoError(t, err)

	resources, results, err := newServiceTokenBuilder(client, "test-account").List(context.Background(), nil, rs.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, resources)
	assert.Nil(t, results)
}
