// Package jobs holds halden-identity's scheduled background work.
package jobs

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// tokenMinter mints the credential a job presents to downstream services.
type tokenMinter interface {
	PlatformToken() (string, error)
}

// Warmup periodically calls the downstream summary so its rollup cache is warm
// before the first customer of the day requests it. It runs with no signed-in
// customer, so it uses the platform credential.
type Warmup struct {
	baseURL  string
	minter   tokenMinter
	client   *http.Client
	interval time.Duration
}

// NewWarmup builds the warmup job.
//
// The client is injected for the same reason the proxy's is: the internal hop
// is TLS or it is not, and that should not be decided in two places.
func NewWarmup(baseURL string, minter tokenMinter, interval time.Duration, client *http.Client) *Warmup {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Warmup{
		baseURL:  baseURL,
		minter:   minter,
		client:   client,
		interval: interval,
	}
}

// Run ticks until the context is cancelled.
func (wm *Warmup) Run(ctx context.Context) {
	ticker := time.NewTicker(wm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := wm.once(ctx); err != nil {
				// Warmup is best-effort; a failure just means the first request
				// pays the rollup cost.
				continue
			}
		}
	}
}

func (wm *Warmup) once(ctx context.Context) error {
	token, err := wm.minter.PlatformToken()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wm.baseURL+"/v1/scans/summary", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := wm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("warmup: downstream status %d", resp.StatusCode)
	}
	return nil
}
