package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zackrossman/halden-identity/internal/auth"
	"github.com/zackrossman/halden-identity/internal/httpx"
)

// capture stands up a stub halden-threat-detection and returns a handler
// pointed at it. call runs a request through the handler and hands back the
// request the stub saw.
type capture struct {
	handler *ThreatScans
	got     *http.Request
}

func newCapture(t *testing.T) *capture {
	t.Helper()

	c := &capture{}
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.got = r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scans":[]}`))
	}))
	t.Cleanup(downstream.Close)

	c.handler = NewThreatScans(Config{
		ThreatDetectionURL: downstream.URL,
		GatewayKey:         "test-gateway-key",
	})
	return c
}

func (c *capture) call(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, r)
	if c.got == nil {
		t.Fatalf("halden-threat-detection received no request (status %d)", rec.Code)
	}
	return rec
}

func authenticated(r *http.Request, tenantID, subject string) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), auth.Claims{Subject: subject, TenantID: tenantID}))
}

func TestThreatScans_ForwardsAuthenticatedTenant(t *testing.T) {
	c := newCapture(t)

	r := authenticated(httptest.NewRequest(http.MethodGet, "/v1/threat-scans", nil), "northwind", "auth0|nw-001")
	rec := c.call(t, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := c.got.Header.Get(httpx.HeaderTenantID); got != "northwind" {
		t.Errorf("%s = %q, want %q", httpx.HeaderTenantID, got, "northwind")
	}
}

func TestThreatScans_AttachesGatewayKey(t *testing.T) {
	c := newCapture(t)

	r := authenticated(httptest.NewRequest(http.MethodGet, "/v1/threat-scans", nil), "contoso", "auth0|co-001")
	c.call(t, r)

	if got := c.got.Header.Get(httpx.HeaderGatewayKey); got != "test-gateway-key" {
		t.Errorf("%s = %q, want %q", httpx.HeaderGatewayKey, got, "test-gateway-key")
	}
}

func TestThreatScans_ForwardsTelemetryHeadersAndQuery(t *testing.T) {
	c := newCapture(t)

	r := httptest.NewRequest(http.MethodGet, "/v1/threat-scans?state=open", nil)
	r.Header.Set(httpx.HeaderRequestID, "req-8f21")
	r.Header.Set(httpx.HeaderClientVersion, "web/4.2.0")
	r.Header.Set(httpx.HeaderLocale, "nb-NO")
	c.call(t, authenticated(r, "northwind", "auth0|nw-002"))

	for header, want := range map[string]string{
		httpx.HeaderRequestID:     "req-8f21",
		httpx.HeaderClientVersion: "web/4.2.0",
		httpx.HeaderLocale:        "nb-NO",
	} {
		if got := c.got.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if got := c.got.URL.Query().Get("state"); got != "open" {
		t.Errorf("query state = %q, want %q", got, "open")
	}
}

func TestThreatScans_StreamsDownstreamResponse(t *testing.T) {
	c := newCapture(t)

	rec := c.call(t, authenticated(httptest.NewRequest(http.MethodGet, "/v1/threat-scans", nil), "contoso", "auth0|co-002"))

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	if got := rec.Body.String(); got != `{"scans":[]}` {
		t.Errorf("body = %q, want %q", got, `{"scans":[]}`)
	}
}

func TestThreatScans_RequiresClaims(t *testing.T) {
	handler := NewThreatScans(Config{ThreatDetectionURL: "http://unused.invalid", GatewayKey: "test-gateway-key"})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/threat-scans", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
