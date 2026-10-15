package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

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

	_, err := New(ctx, "", "token", "", "", "")
	require.ErrorIs(t, err, ErrMissingAccountID)

	_, err = New(ctx, "acct", "", "", "", "")
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
	// The header format the Cloudflare v4 API sends.
	w.Header().Set("Ratelimit", `"default";r=1199;t=1`)
	w.Header().Set("Ratelimit-Policy", `"default";q=1200;w=300`)
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

	_, err = c.VerifyAccess(context.Background())
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
			_, err = c.VerifyAccess(context.Background())
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
	require.ErrorIs(t, err, ErrMemberRolesXorPolicies)

	_, _, err = c.UpdateAccountMember(context.Background(), "m1", AccountMember{
		Roles:    []AccountRole{{ID: "r1"}},
		Policies: []Policy{{Access: "allow"}},
	})
	require.ErrorIs(t, err, ErrMemberRolesXorPolicies)
}

func TestExtractRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	header := func(values map[string]string) http.Header {
		h := http.Header{}
		for k, v := range values {
			h.Set(k, v)
		}
		return h
	}

	tests := []struct {
		name       string
		statusCode int
		header     http.Header
		wantNil    bool
		limit      int64
		remaining  int64
		resetIn    time.Duration
		noReset    bool
		status     v2.RateLimitDescription_Status
	}{
		{
			name:       "structured headers",
			statusCode: http.StatusOK,
			header:     header(map[string]string{"Ratelimit": `"default";r=1199;t=1`, "Ratelimit-Policy": `"default";q=1200;w=300`}),
			limit:      1200, remaining: 1199, resetIn: time.Second,
			status: v2.RateLimitDescription_STATUS_OK,
		},
		{
			name:       "several policies, fewest remaining wins",
			statusCode: http.StatusOK,
			header:     header(map[string]string{"Ratelimit": `"default";r=900;t=100, "burst";r=3;t=2`, "Ratelimit-Policy": `"default";q=1200;w=300, "burst";q=10;w=5`}),
			limit:      10, remaining: 3, resetIn: 2 * time.Second,
			status: v2.RateLimitDescription_STATUS_OK,
		},
		{
			name:       "no policy header",
			statusCode: http.StatusOK,
			header:     header(map[string]string{"Ratelimit": `"default";r=5;t=10`}),
			limit:      0, remaining: 5, resetIn: 10 * time.Second,
			status: v2.RateLimitDescription_STATUS_OK,
		},
		{
			name:       "429 is over limit",
			statusCode: http.StatusTooManyRequests,
			header:     header(map[string]string{"Ratelimit": `"default";r=0;t=42`, "Ratelimit-Policy": `"default";q=1200;w=300`}),
			limit:      1200, remaining: 0, resetIn: 42 * time.Second,
			status: v2.RateLimitDescription_STATUS_OVERLIMIT,
		},
		{
			name:       "tie on remaining goes to the later reset",
			statusCode: http.StatusTooManyRequests,
			header:     header(map[string]string{"Ratelimit": `"burst";r=0;t=1, "default";r=0;t=300`, "Ratelimit-Policy": `"burst";q=10;w=5, "default";q=1200;w=300`}),
			limit:      1200, remaining: 0, resetIn: 300 * time.Second,
			status: v2.RateLimitDescription_STATUS_OVERLIMIT,
		},
		{
			name:       "zero remaining on a success is not over the limit",
			statusCode: http.StatusOK,
			header:     header(map[string]string{"Ratelimit": `"default";r=0;t=30`}),
			limit:      0, remaining: 0, resetIn: 30 * time.Second,
			status: v2.RateLimitDescription_STATUS_UNSPECIFIED,
		},
		{
			name:       "item without t has no reset",
			statusCode: http.StatusOK,
			header:     header(map[string]string{"Ratelimit": `"default";r=5`}),
			limit:      0, remaining: 5, noReset: true,
			status: v2.RateLimitDescription_STATUS_OK,
		},
		{
			name:       "separate headers fall back to the SDK parser",
			statusCode: http.StatusOK,
			header:     header(map[string]string{"X-Ratelimit-Limit": "100", "X-Ratelimit-Remaining": "7"}),
			limit:      100, remaining: 7,
			status: v2.RateLimitDescription_STATUS_OK,
		},
		{
			name:       "malformed structured header falls back",
			statusCode: http.StatusOK,
			header:     header(map[string]string{"Ratelimit": `"default";r=abc;t=`}),
			limit:      0, remaining: 0,
			status: v2.RateLimitDescription_STATUS_UNSPECIFIED,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := extractRateLimit(tt.statusCode, tt.header, now)
			require.NotNil(t, desc)
			assert.Equal(t, tt.limit, desc.GetLimit())
			assert.Equal(t, tt.remaining, desc.GetRemaining())
			assert.Equal(t, tt.status, desc.GetStatus())
			if tt.noReset {
				assert.Nil(t, desc.GetResetAt())
			}
			if tt.resetIn > 0 {
				assert.True(t, now.Add(tt.resetIn).Equal(desc.GetResetAt().AsTime()), "reset at %s", desc.GetResetAt().AsTime())
			}
		})
	}
}

func TestExtractRateLimitReadsEveryHeaderLine(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := http.Header{}
	h.Add("Ratelimit", `"default";r=900;t=100`)
	h.Add("Ratelimit", `"burst";r=0;t=2`)

	desc := extractRateLimit(http.StatusOK, h, now)
	require.NotNil(t, desc)
	assert.Equal(t, int64(0), desc.GetRemaining())
	assert.True(t, now.Add(2*time.Second).Equal(desc.GetResetAt().AsTime()))
}

func TestExtractRateLimitPrefersLaterRetryAfterOn429(t *testing.T) {
	now := time.Now()
	h := http.Header{}
	h.Set("Ratelimit", `"default";r=0;t=1`)
	h.Set("Retry-After", "300")

	desc := extractRateLimit(http.StatusTooManyRequests, h, now)
	require.NotNil(t, desc)
	assert.WithinDuration(t, now.Add(300*time.Second), desc.GetResetAt().AsTime(), 5*time.Second)

	// A Retry-After earlier than the structured reset does not shorten it.
	h.Set("Ratelimit", `"default";r=0;t=600`)
	desc = extractRateLimit(http.StatusTooManyRequests, h, now)
	require.NotNil(t, desc)
	assert.True(t, now.Add(600*time.Second).Equal(desc.GetResetAt().AsTime()))
}

func TestMalformedRateLimitHeaderDoesNotFailRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Ratelimit", `"default";r=;t=oops`)
		w.Header().Set("X-Ratelimit-Limit", "not-a-number")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`))
	}))
	defer server.Close()

	c, err := New(context.Background(), "acct", "token", "", "", server.URL)
	require.NoError(t, err)
	_, err = c.VerifyAccess(context.Background())
	require.NoError(t, err)
}

// TestRateLimitedErrorCarriesCloudflareReset checks that a 429's gRPC status
// carries the reset time from Cloudflare's Ratelimit header, which the SDK's
// retryer uses to decide how long to wait.
func TestRateLimitedErrorCarriesCloudflareReset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Ratelimit", `"default";r=0;t=120`)
		w.Header().Set("Ratelimit-Policy", `"default";q=1200;w=300`)
		writeError(w, http.StatusTooManyRequests, "Rate limited")
	}))
	defer server.Close()

	c, err := New(context.Background(), "acct", "token", "", "", server.URL)
	require.NoError(t, err)

	before := time.Now()
	_, _, _, err = c.ListAccessUsers(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Rate limited")

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())

	var desc *v2.RateLimitDescription
	for _, detail := range st.Details() {
		if d, ok := detail.(*v2.RateLimitDescription); ok {
			desc = d
			break
		}
	}
	require.NotNil(t, desc, "expected rate-limit details on the status")
	assert.Equal(t, v2.RateLimitDescription_STATUS_OVERLIMIT, desc.GetStatus())
	assert.Equal(t, int64(1200), desc.GetLimit())
	assert.Equal(t, int64(0), desc.GetRemaining())
	assert.WithinDuration(t, before.Add(120*time.Second), desc.GetResetAt().AsTime(), 5*time.Second)
}
