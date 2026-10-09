package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PageSize is the number of items requested per page from paginated endpoints.
const PageSize = 50

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

// nextPageToken returns the token for the page after page, or "" when page is
// the last one. The page count comes from total_pages, or from total_count and
// per_page when total_pages is absent (the same fallback cloudflare-go's own
// pagination uses). With neither, a full page is assumed to have a successor
// and a short page ends the sequence.
func nextPageToken(page int, info *cloudflare.ResultInfo, received int) string {
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
	case totalPages == 0 && received == PageSize:
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

// cloudflareHTTPStatus returns the HTTP status behind a typed cloudflare-go
// API error, or 0 when err is not one. cloudflare-go keeps the status
// unexported but assigns each typed error from a fixed status: 401
// AuthorizationError, 403 AuthenticationError, 404 NotFoundError,
// 429 RatelimitError, 5xx ServiceError, and any other 4xx RequestError.
func cloudflareHTTPStatus(err error) int {
	var (
		authorization  *cloudflare.AuthorizationError
		authentication *cloudflare.AuthenticationError
		notFound       *cloudflare.NotFoundError
		rateLimit      *cloudflare.RatelimitError
		service        *cloudflare.ServiceError
		request        *cloudflare.RequestError
	)

	switch {
	case errors.As(err, &authorization):
		return http.StatusUnauthorized
	case errors.As(err, &authentication):
		return http.StatusForbidden
	case errors.As(err, &notFound):
		return http.StatusNotFound
	case errors.As(err, &rateLimit):
		return http.StatusTooManyRequests
	case errors.As(err, &service):
		return http.StatusInternalServerError
	case errors.As(err, &request):
		return http.StatusBadRequest
	default:
		return 0
	}
}

// mapCloudflareError attaches a gRPC status to a cloudflare-go error so the
// SDK can tell retryable failures from fatal ones. An existing non-Unknown
// gRPC status is kept. Errors that are not Cloudflare API responses (network
// failures, decode errors) are returned unchanged. The original error stays in
// the chain, so errors.As still finds the typed cloudflare-go error.
func mapCloudflareError(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}

	httpStatus := cloudflareHTTPStatus(err)
	if httpStatus == 0 {
		return err
	}

	return uhttp.WrapErrors(uhttp.GrpcCodeFromHTTPStatus(httpStatus), "cloudflare API request failed", err)
}

type rateLimitCaptureKey struct{}

// rateLimitCapture receives the rate-limit description parsed from the
// response headers of the requests made under one client call.
type rateLimitCapture struct {
	desc *v2.RateLimitDescription
}

// withRateLimitCapture returns a context whose requests record their
// rate-limit headers into the returned capture.
func withRateLimitCapture(ctx context.Context) (context.Context, *rateLimitCapture) {
	capture := &rateLimitCapture{}
	return context.WithValue(ctx, rateLimitCaptureKey{}, capture), capture
}

// annotations returns the captured rate-limit description as annotations. It
// is attached unconditionally; a description with no reset time is ignored
// downstream.
func (r *rateLimitCapture) annotations() annotations.Annotations {
	desc := r.desc
	if desc == nil {
		desc = &v2.RateLimitDescription{}
	}

	var annos annotations.Annotations
	annos.WithRateLimiting(desc)
	return annos
}

// rateLimitTransport records rate-limit response headers into the capture
// carried by the request context. cloudflare-go builds and sends requests
// itself, so the transport is the only place the response headers are seen.
type rateLimitTransport struct {
	base http.RoundTripper
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp == nil {
		return resp, err
	}

	capture, ok := req.Context().Value(rateLimitCaptureKey{}).(*rateLimitCapture)
	if !ok {
		return resp, err
	}

	// A malformed rate-limit header only loses the annotation; the response
	// itself is still returned to cloudflare-go.
	desc, rlErr := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header)
	if rlErr == nil && desc != nil {
		capture.desc = desc
	}

	return resp, err
}
