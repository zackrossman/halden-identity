// Package httpx holds the HTTP plumbing shared between Halden services.
package httpx

import (
	"net/http"
	"strings"
)

// Header names propagated between Halden services. See
// docs/platform/internal-service-contract.md.
const (
	HeaderTenantID      = "X-Halden-Tenant-ID"
	HeaderGatewayKey    = "X-Halden-Gateway-Key"
	HeaderRequestID     = "X-Halden-Request-ID"
	HeaderClientVersion = "X-Halden-Client-Version"
	HeaderLocale        = "X-Halden-Locale"
)

// CopyClientContextHeaders forwards the caller's X-Halden-* context headers onto an
// outbound service call so downstream logs correlate with the originating request.
func CopyClientContextHeaders(src *http.Request, dst *http.Request) {
	for name, values := range src.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Halden-") && len(values) > 0 {
			dst.Header.Set(http.CanonicalHeaderKey(name), values[0])
		}
	}
}
