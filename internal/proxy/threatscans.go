// Package proxy forwards authenticated customer requests to internal Halden services.
package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/zackrossman/halden-identity/internal/auth"
	"github.com/zackrossman/halden-identity/internal/httpx"
)

// Minter mints the downstream token a proxied call presents.
type Minter interface {
	UserToken(claims auth.Claims) (string, error)
	PlatformToken() (string, error)
}

// ThreatScans proxies the threat-scan endpoints to halden-threat-detection.
type ThreatScans struct {
	baseURL string
	minter  Minter
	client  *http.Client
}

// NewThreatScans builds the proxy against the downstream base URL.
func NewThreatScans(baseURL string, minter Minter) *ThreatScans {
	return &ThreatScans{
		baseURL: baseURL,
		minter:  minter,
		client:  &http.Client{Timeout: 20 * time.Second},
	}
}

// List serves GET /v1/threat-scans: the caller's own tenant's scans.
func (h *ThreatScans) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := h.minter.UserToken(claims)
	if err != nil {
		slog.ErrorContext(r.Context(), "mint downstream token", "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	h.forward(w, r, "/v1/scans", token)
}

// Summary serves GET /v1/threat-scans/summary. The summary figures come from the
// platform rollup, which runs under the platform credential.
func (h *ThreatScans) Summary(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := h.minter.PlatformToken()
	if err != nil {
		slog.ErrorContext(r.Context(), "mint downstream token", "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	h.forward(w, r, "/v1/scans/summary", token)
}

func (h *ThreatScans) forward(w http.ResponseWriter, r *http.Request, path, token string) {
	out, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.baseURL+path, nil)
	if err != nil {
		slog.ErrorContext(r.Context(), "build threat-detection request", "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	out.URL.RawQuery = r.URL.RawQuery
	out.Header.Set("Authorization", "Bearer "+token)
	httpx.ForwardTelemetryHeaders(r, out)

	resp, err := h.client.Do(out)
	if err != nil {
		slog.ErrorContext(r.Context(), "call threat-detection", "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		slog.WarnContext(r.Context(), "stream threat-detection response", "error", err)
	}
}
