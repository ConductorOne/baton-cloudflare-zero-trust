package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// pageSize is the number of items requested per page from paginated endpoints.
const pageSize = 50

// parsePageToken converts a page token into a 1-based Cloudflare page number.
// An empty token is the first page.
func parsePageToken(token string) (int, error) {
	if token == "" {
		return 1, nil
	}

	page, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("invalid page token %q: %w", token, err)
	}
	if page < 1 {
		return 0, fmt.Errorf("invalid page token %q: page must be at least 1", token)
	}

	return page, nil
}

// pageQuery returns the query parameters that request one page.
func pageQuery(page int) url.Values {
	return url.Values{
		"page":     []string{strconv.Itoa(page)},
		"per_page": []string{strconv.Itoa(pageSize)},
	}
}

// nextPageToken returns the token for the page after page, or "" when page is
// the last one. The page count comes from total_pages, or from total_count and
// per_page when total_pages is absent. With neither, a full page is assumed
// to have a successor and a short page ends the sequence.
func nextPageToken(page int, info *resultInfo, received int) string {
	totalPages := 0
	if info != nil {
		totalPages = info.TotalPages
		if totalPages == 0 && info.Total > 0 && info.PerPage > 0 {
			totalPages = (info.Total + info.PerPage - 1) / info.PerPage
		}
	}

	switch {
	case totalPages > 0 && page < totalPages:
		return strconv.Itoa(page + 1)
	case totalPages == 0 && received == pageSize:
		return strconv.Itoa(page + 1)
	default:
		return ""
	}
}

// validateBaseURL rejects a base URL override that is not an absolute
// http(s) URL with a host.
func validateBaseURL(baseURL string) error {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL %q: %w", baseURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid base URL %q: must include http:// or https:// scheme", baseURL)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid base URL %q: missing host", baseURL)
	}
	return nil
}

// decodeEnvelope decodes the Cloudflare response envelope into env. For a
// non-2xx response it returns the API's error messages; uhttp joins that
// error after the gRPC status it derives from the HTTP status code.
func decodeEnvelope(env *envelope) uhttp.DoOption {
	return func(resp *uhttp.WrapperResponse) error {
		success := resp.StatusCode >= 200 && resp.StatusCode < 300
		if err := json.Unmarshal(resp.Body, env); err != nil {
			if success {
				return fmt.Errorf("decode response (HTTP %d): %w", resp.StatusCode, err)
			}
			// Non-JSON error bodies (an HTML page from the edge, for example)
			// are not echoed into the error.
			return fmt.Errorf("cloudflare API error (HTTP %d)", resp.StatusCode)
		}
		if !success {
			return fmt.Errorf("cloudflare API error (HTTP %d): %s", resp.StatusCode, env.Message())
		}
		return nil
	}
}

// captureRateLimit records the rate-limit headers of a response into desc. A
// malformed header only loses the annotation; it never fails the request.
func captureRateLimit(desc **v2.RateLimitDescription) uhttp.DoOption {
	return func(resp *uhttp.WrapperResponse) error {
		if parsed := extractRateLimit(resp.StatusCode, resp.Header, time.Now()); parsed != nil {
			*desc = parsed
		}
		return nil
	}
}

// extractRateLimit reads Cloudflare's structured rate-limit headers, falling
// back to the SDK's parser for the separate X-Ratelimit-*, Ratelimit-* and
// Retry-After headers, which the SDK reads but Cloudflare does not send on
// its v4 API. On a 429, a Retry-After later than the structured reset wins,
// so the retryer never comes back before the server will accept requests.
func extractRateLimit(statusCode int, header http.Header, now time.Time) *v2.RateLimitDescription {
	desc := parseStructuredRateLimit(statusCode, header, now)
	if desc == nil {
		sdkDesc, err := ratelimit.ExtractRateLimitData(statusCode, &header)
		if err != nil {
			return nil
		}
		return sdkDesc
	}

	if statusCode == http.StatusTooManyRequests && header.Get("Retry-After") != "" {
		sdkDesc, err := ratelimit.ExtractRateLimitData(statusCode, &header)
		if err == nil && sdkDesc.GetResetAt().AsTime().After(desc.GetResetAt().AsTime()) {
			desc.SetResetAt(sdkDesc.GetResetAt())
		}
	}
	return desc
}

// parseStructuredRateLimit parses the structured headers from the IETF
// RateLimit fields draft, which Cloudflare sends as
//
//	Ratelimit: "default";r=<remaining>;t=<seconds until reset>
//	Ratelimit-Policy: "default";q=<quota>;w=<window seconds>
//
// When Ratelimit lists several policies, the one with the fewest remaining
// requests is used, as it is the one that throttles first; a tie goes to the
// later reset. An item without t has no reset time. It returns nil when no
// Ratelimit item carries a usable r.
func parseStructuredRateLimit(statusCode int, header http.Header, now time.Time) *v2.RateLimitDescription {
	var (
		chosen    *structuredItem
		remaining int64
		reset     int64
		hasReset  bool
	)
	limits := parseStructuredList(header.Values("Ratelimit"))
	for i := range limits {
		item := &limits[i]
		r, err := strconv.ParseInt(item.params["r"], 10, 64)
		if err != nil || r < 0 {
			continue
		}
		var t int64
		tStr, itemHasReset := item.params["t"]
		if itemHasReset {
			t, err = strconv.ParseInt(tStr, 10, 64)
			if err != nil || t < 0 {
				continue
			}
		}
		if chosen == nil || r < remaining || (r == remaining && t > reset) {
			chosen, remaining, reset, hasReset = item, r, t, itemHasReset
		}
	}
	if chosen == nil {
		return nil
	}

	var limit int64
	for _, policy := range parseStructuredList(header.Values("Ratelimit-Policy")) {
		if policy.name != chosen.name {
			continue
		}
		if q, err := strconv.ParseInt(policy.params["q"], 10, 64); err == nil && q > 0 {
			limit = q
		}
		break
	}

	// Same status rules as the SDK's parser: OK while requests remain, and
	// over the limit only on an actual 429.
	var rlStatus v2.RateLimitDescription_Status
	switch {
	case statusCode == http.StatusTooManyRequests:
		rlStatus = v2.RateLimitDescription_STATUS_OVERLIMIT
		remaining = 0
	case remaining > 0:
		rlStatus = v2.RateLimitDescription_STATUS_OK
	}

	desc := v2.RateLimitDescription_builder{
		Status:    rlStatus,
		Limit:     limit,
		Remaining: remaining,
	}.Build()
	if hasReset {
		desc.SetResetAt(timestamppb.New(now.Add(time.Duration(reset) * time.Second)))
	}
	return desc
}

// structuredItem is one member of a structured-field list: a name and its
// parameters.
type structuredItem struct {
	name   string
	params map[string]string
}

// parseStructuredList parses structured-field list values such as
// `"default";r=10;t=5, "burst";r=2;t=1` into their items, in order. A list
// may be split across several header lines, so every value is read.
func parseStructuredList(values []string) []structuredItem {
	var items []structuredItem
	for _, value := range values {
		for _, member := range strings.Split(value, ",") {
			parts := strings.Split(member, ";")
			name := strings.Trim(strings.TrimSpace(parts[0]), `"`)
			if name == "" {
				continue
			}
			params := make(map[string]string, len(parts)-1)
			for _, part := range parts[1:] {
				key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok {
					params[strings.ToLower(key)] = strings.Trim(val, `"`)
				}
			}
			items = append(items, structuredItem{name: name, params: params})
		}
	}
	return items
}

// withRateLimitDetails puts a gRPC status carrying desc ahead of err. The
// SDK's retryer reads rate-limit details from the first status in the error
// chain, and uhttp's own status only reflects the headers its parser
// understands, so without this a Cloudflare 429 backs off on a default delay
// instead of Cloudflare's reset time.
func withRateLimitDetails(err error, desc *v2.RateLimitDescription) error {
	code := codes.Unavailable
	if st, ok := status.FromError(err); ok {
		code = st.Code()
	}

	detailed, detailsErr := status.New(code, "cloudflare API rate limit exceeded").WithDetails(desc)
	if detailsErr != nil {
		return err
	}
	return errors.Join(detailed.Err(), err)
}

// rateLimitAnnotations returns desc as annotations. It is attached
// unconditionally; a description with no reset time is ignored downstream.
func rateLimitAnnotations(desc *v2.RateLimitDescription) annotations.Annotations {
	if desc == nil {
		desc = &v2.RateLimitDescription{}
	}

	var annos annotations.Annotations
	annos.WithRateLimiting(desc)
	return annos
}
