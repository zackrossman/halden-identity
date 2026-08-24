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

// Config holds the settings the threat-scan proxy needs.
type Config struct {
	ThreatDetectionURL string
	GatewayKey         string
}

// ThreatScans serves GET /v1/threat-scans by calling halden-threat-detection.
type ThreatScans struct {
	cfg    Config
	client *http.Client
}

// NewThreatScans builds the handler.
func NewThreatScans(cfg Config) *ThreatScans {
	return &ThreatScans{
		cfg:    cfg,
		client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (h *ThreatScans) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	out, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.cfg.ThreatDetectionURL+"/v1/scans", nil)
	if err != nil {
		slog.ErrorContext(r.Context(), "build threat-detection request", "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	out.URL.RawQuery = r.URL.RawQuery

	out.Header.Set(httpx.HeaderTenantID, claims.TenantID)
	out.Header.Set(httpx.HeaderGatewayKey, h.cfg.GatewayKey)
	httpx.CopyClientContextHeaders(r, out)

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
