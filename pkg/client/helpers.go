package client

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
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
		parsed, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header)
		if err == nil && parsed != nil {
			*desc = parsed
		}
		return nil
	}
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
