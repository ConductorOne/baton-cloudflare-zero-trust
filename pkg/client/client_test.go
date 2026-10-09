package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestParsePageToken(t *testing.T) {
	page, err := parsePageToken("")
	require.NoError(t, err)
	assert.Equal(t, 1, page)

	page, err = parsePageToken("3")
	require.NoError(t, err)
	assert.Equal(t, 3, page)

	_, err = parsePageToken("abc")
	require.Error(t, err)
	_, err = parsePageToken("0")
	require.Error(t, err)
}

func TestNextPageToken(t *testing.T) {
	tests := []struct {
		name     string
		page     int
		info     *cloudflare.ResultInfo
		received int
		want     string
	}{
		{name: "total_pages, more", page: 1, info: &cloudflare.ResultInfo{TotalPages: 3}, received: PageSize, want: "2"},
		{name: "total_pages, last", page: 3, info: &cloudflare.ResultInfo{TotalPages: 3}, received: 1, want: ""},
		{name: "total_count fallback, more", page: 1, info: &cloudflare.ResultInfo{Total: PageSize + 1, PerPage: PageSize}, received: PageSize, want: "2"},
		{name: "total_count fallback, last", page: 2, info: &cloudflare.ResultInfo{Total: PageSize + 1, PerPage: PageSize}, received: 1, want: ""},
		{name: "no info, full page", page: 1, info: nil, received: PageSize, want: "2"},
		{name: "no info, short page", page: 1, info: &cloudflare.ResultInfo{}, received: 3, want: ""},
		{name: "no info, empty page", page: 4, info: nil, received: 0, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, nextPageToken(tt.page, tt.info, tt.received))
		})
	}
}

func TestValidateBaseURL(t *testing.T) {
	require.NoError(t, validateBaseURL("https://api.cloudflare.com/client/v4"))
	require.NoError(t, validateBaseURL("http://127.0.0.1:8080"))
	require.Error(t, validateBaseURL("api.cloudflare.com"))
	require.Error(t, validateBaseURL("https://"))
	require.Error(t, validateBaseURL("://bad"))
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	ctx := context.Background()

	_, err := New(ctx, "acct", "", "", "", "")
	require.Error(t, err, "missing credentials")

	_, err = New(ctx, "acct", "", "key", "", "")
	require.Error(t, err, "API key without email")

	_, err = New(ctx, "acct", "token", "", "", "not-a-url")
	require.Error(t, err, "invalid base URL")

	c, err := New(ctx, "acct", "token", "", "", "")
	require.NoError(t, err)
	require.NotNil(t, c.api)
}

func TestMapCloudflareError(t *testing.T) {
	assert.NoError(t, mapCloudflareError(nil))

	plain := errors.New("connection reset")
	assert.Equal(t, plain, mapCloudflareError(plain))

	existing := status.Error(codes.Unavailable, "already classified")
	assert.Equal(t, existing, mapCloudflareError(existing))

	tests := []struct {
		err  error
		code codes.Code
	}{
		{err: &cloudflare.AuthorizationError{}, code: codes.Unauthenticated},
		{err: &cloudflare.AuthenticationError{}, code: codes.PermissionDenied},
		{err: &cloudflare.NotFoundError{}, code: codes.NotFound},
		{err: &cloudflare.RatelimitError{}, code: codes.Unavailable},
		{err: &cloudflare.RequestError{}, code: codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%T", tt.err), func(t *testing.T) {
			mapped := mapCloudflareError(fmt.Errorf("wrapped: %w", tt.err))
			st, ok := status.FromError(mapped)
			require.True(t, ok)
			assert.Equal(t, tt.code, st.Code())
		})
	}
}

// writeMembersPage serves one page of account members in Cloudflare's
// response envelope, with a rate-limit header for the annotation.
func writeMembersPage(t *testing.T, w http.ResponseWriter, page, totalPages int) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Ratelimit-Limit", "1200")
	w.Header().Set("Ratelimit-Remaining", "1199")
	w.Header().Set("Ratelimit-Reset", "300")
	require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"errors":   []interface{}{},
		"messages": []interface{}{},
		"result": []map[string]interface{}{
			{"id": fmt.Sprintf("member-%d", page), "user": map[string]interface{}{"id": fmt.Sprintf("user-%d", page)}},
		},
		"result_info": map[string]interface{}{
			"page":        page,
			"per_page":    PageSize,
			"count":       1,
			"total_count": totalPages,
			"total_pages": totalPages,
		},
	}))
}

func TestListAccountMembersPagesAndAnnotates(t *testing.T) {
	const totalPages = 2
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/accounts/acct/members", r.URL.Path)
		require.Equal(t, strconv.Itoa(PageSize), r.URL.Query().Get("per_page"))
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		require.NoError(t, err)
		writeMembersPage(t, w, page, totalPages)
	}))
	defer server.Close()

	c, err := New(context.Background(), "acct", "token", "", "", server.URL)
	require.NoError(t, err)

	members, next, annos, err := c.ListAccountMembers(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "member-1", members[0].ID)
	assert.Equal(t, "2", next)

	rl := &v2.RateLimitDescription{}
	ok, err := annos.Pick(rl)
	require.NoError(t, err)
	require.True(t, ok, "expected a rate-limit annotation")
	assert.Equal(t, int64(1200), rl.GetLimit())
	assert.Equal(t, int64(1199), rl.GetRemaining())

	members, next, _, err = c.ListAccountMembers(context.Background(), next)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "member-2", members[0].ID)
	assert.Empty(t, next)
}

func TestClientMapsAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"messages":[],"result":null}`))
	}))
	defer server.Close()

	c, err := New(context.Background(), "acct", "token", "", "", server.URL)
	require.NoError(t, err)

	_, annos, err := c.ListAccessGroups(context.Background())
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	var forbidden *cloudflare.AuthenticationError
	assert.ErrorAs(t, err, &forbidden, "the typed cloudflare-go error stays in the chain")
	assert.NotEmpty(t, annos, "rate-limit annotation is attached even on failure")
}
