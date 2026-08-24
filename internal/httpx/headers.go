// Package httpx holds the HTTP plumbing shared between Halden services.
package httpx

import "net/http"

// Telemetry headers forwarded to downstream services for log correlation. They
// carry no authority.
const (
	HeaderRequestID     = "X-Halden-Request-ID"
	HeaderClientVersion = "X-Halden-Client-Version"
	HeaderLocale        = "X-Halden-Locale"
)

var telemetryHeaders = []string{HeaderRequestID, HeaderClientVersion, HeaderLocale}

// ForwardTelemetryHeaders copies the caller's telemetry headers onto an outbound
// service call so downstream logs correlate with the originating request.
func ForwardTelemetryHeaders(src *http.Request, dst *http.Request) {
	for _, name := range telemetryHeaders {
		if v := src.Header.Get(name); v != "" {
			dst.Header.Set(name, v)
		}
	}
}
