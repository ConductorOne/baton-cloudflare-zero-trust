package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

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
		info     *resultInfo
		received int
		want     string
	}{
		{name: "total_pages, more", page: 1, info: &resultInfo{TotalPages: 3}, received: pageSize, want: "2"},
		{name: "total_pages, last", page: 3, info: &resultInfo{TotalPages: 3}, received: 1, want: ""},
		{name: "total_count fallback, more", page: 1, info: &resultInfo{Total: pageSize + 1, PerPage: pageSize}, received: pageSize, want: "2"},
		{name: "total_count fallback, last", page: 2, info: &resultInfo{Total: pageSize + 1, PerPage: pageSize}, received: 1, want: ""},
		{name: "no info, full page", page: 1, info: nil, received: pageSize, want: "2"},
		{name: "no info, short page", page: 1, info: &resultInfo{}, received: 3, want: ""},
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
	require.NotNil(t, c.http)
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
			"per_page":    pageSize,
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
		require.Equal(t, strconv.Itoa(pageSize), r.URL.Query().Get("per_page"))
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

// writeError serves a Cloudflare error envelope with the given status.
func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, `{"success":false,"errors":[{"code":10000,"message":%q}],"messages":[],"result":null}`, message)
}

func TestClientMapsAPIErrors(t *testing.T) {
	tests := []struct {
		status int
		code   codes.Code
	}{
		{status: http.StatusUnauthorized, code: codes.Unauthenticated},
		{status: http.StatusForbidden, code: codes.PermissionDenied},
		{status: http.StatusNotFound, code: codes.NotFound},
		{status: http.StatusTooManyRequests, code: codes.Unavailable},
		{status: http.StatusInternalServerError, code: codes.Unavailable},
		{status: http.StatusServiceUnavailable, code: codes.Unavailable},
		{status: http.StatusBadRequest, code: codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.Header().Set("Retry-After", "30")
				writeError(w, tt.status, "Authentication error")
			}))
			defer server.Close()

			c, err := New(context.Background(), "acct", "token", "", "", server.URL)
			require.NoError(t, err)

			_, _, annos, err := c.ListAccessGroups(context.Background(), "")
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.code, st.Code())
			assert.Contains(t, err.Error(), "10000: Authentication error", "the API's error message is kept")
			assert.Equal(t, 1, requests, "the client does not retry; the SDK does")
			assert.NotEmpty(t, annos, "rate-limit annotation is attached even on failure")
		})
	}
}

func TestClientRejectsUnsuccessfulEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusOK, "something went wrong")
	}))
	defer server.Close()

	c, err := New(context.Background(), "acct", "token", "", "", server.URL)
	require.NoError(t, err)

	_, err = c.AccessKeysConfig(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "something went wrong")
}

func TestClientAuthHeaders(t *testing.T) {
	tests := []struct {
		name              string
		token, key, email string
		wantAuth, wantKey string
		wantEmail         string
	}{
		{name: "token", token: "tok", wantAuth: "Bearer tok"},
		{name: "token wins over key", token: "tok", key: "k", email: "e@x.com", wantAuth: "Bearer tok"},
		{name: "key and email", key: "k", email: "e@x.com", wantKey: "k", wantEmail: "e@x.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.wantAuth, r.Header.Get("Authorization"))
				assert.Equal(t, tt.wantKey, r.Header.Get("X-Auth-Key"))
				assert.Equal(t, tt.wantEmail, r.Header.Get("X-Auth-Email"))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`))
			}))
			defer server.Close()

			c, err := New(context.Background(), "acct", tt.token, tt.key, tt.email, server.URL)
			require.NoError(t, err)
			_, err = c.AccessKeysConfig(context.Background())
			require.NoError(t, err)
		})
	}
}

// TestGetAccessGroupBypassesCache checks that a read feeding a write is not
// served from uhttp's GET cache, which would let back-to-back grants on one
// group overwrite each other.
func TestGetAccessGroupBypassesCache(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "/accounts/acct/access/groups/g1", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"g1","name":"v%d"}}`, requests)
	}))
	defer server.Close()

	c, err := New(context.Background(), "acct", "token", "", "", server.URL)
	require.NoError(t, err)

	first, _, err := c.GetAccessGroup(context.Background(), "g1")
	require.NoError(t, err)
	second, _, err := c.GetAccessGroup(context.Background(), "g1")
	require.NoError(t, err)
	assert.Equal(t, "v1", first.Name)
	assert.Equal(t, "v2", second.Name)
}

func TestUpdateAccessGroupIncludeKeepsOtherFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Equal(t, "/accounts/acct/access/groups/g1", r.URL.Path)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "Engineering", body["name"])
		assert.Equal(t, []interface{}{map[string]interface{}{"email": map[string]interface{}{"email": "new@x.com"}}}, body["include"])
		assert.Equal(t, []interface{}{map[string]interface{}{"geo": map[string]interface{}{"country_code": "US"}}}, body["require"])
		assert.Equal(t, []interface{}{}, body["exclude"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"g1"}}`))
	}))
	defer server.Close()

	c, err := New(context.Background(), "acct", "token", "", "", server.URL)
	require.NoError(t, err)

	group := &AccessGroup{
		ID:      "g1",
		Name:    "Engineering",
		Include: []interface{}{map[string]interface{}{"email": map[string]interface{}{"email": "old@x.com"}}},
		Require: []interface{}{map[string]interface{}{"geo": map[string]interface{}{"country_code": "US"}}},
		Exclude: []interface{}{},
	}
	_, err = c.UpdateAccessGroupInclude(context.Background(), group, []interface{}{map[string]interface{}{"email": map[string]interface{}{"email": "new@x.com"}}})
	require.NoError(t, err)
}

func TestUpdateAccountMemberRequiresRolesOrPolicies(t *testing.T) {
	c, err := New(context.Background(), "acct", "token", "", "", "")
	require.NoError(t, err)

	_, _, err = c.UpdateAccountMember(context.Background(), "m1", AccountMember{})
	require.ErrorIs(t, err, ErrMissingMemberRolesOrPolicies)

	_, _, err = c.UpdateAccountMember(context.Background(), "m1", AccountMember{
		Roles:    []AccountRole{{ID: "r1"}},
		Policies: []Policy{{Access: "allow"}},
	})
	require.ErrorIs(t, err, ErrMissingMemberRolesOrPolicies)
}
