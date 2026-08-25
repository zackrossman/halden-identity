// Package config loads the service settings from the environment.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zackrossman/halden-identity/internal/auth"
	"github.com/zackrossman/halden-identity/internal/httpx"
)

const defaultThreatDetectionURL = "http://halden-threat-detection.halden.svc.cluster.local:8000"

// Auth0 holds the settings used to validate incoming access tokens.
type Auth0 struct {
	JWKSURL  string
	Issuer   string
	Audience string
	// Floor on how often the JWKS is refetched, and therefore the ceiling on
	// how long a key Auth0 has already revoked still validates tokens here.
	CacheMinTTL time.Duration
}

// Config is the full service configuration.
type Config struct {
	ListenAddr string
	// PEM-encoded RSA private key used to sign downstream tokens with RS256.
	// Required: internal services verify against the matching public key and
	// accept nothing else, so a missing key means every downstream call is
	// refused. Failing here stops the process instead.
	InternalTokenPrivateKey string
	ThreatDetectionURL      string
	// TLS material for calling halden-threat-detection. Optional: with none
	// set, calls use the default transport, which is how this ran before
	// internal TLS existed. Verification is never disabled.
	ThreatDetectionTLS httpx.TLSConfig
	Auth0              Auth0
}

// Load reads the configuration from the environment. Every secret and endpoint
// comes from the environment; nothing is baked into the binary.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:              valueOr("HALDEN_LISTEN_ADDR", ":8080"),
		InternalTokenPrivateKey: os.Getenv("HALDEN_INTERNAL_TOKEN_PRIVATE_KEY"),
		ThreatDetectionURL:      strings.TrimRight(valueOr("THREAT_DETECTION_URL", defaultThreatDetectionURL), "/"),
		ThreatDetectionTLS: httpx.TLSConfig{
			CABundlePath:   os.Getenv("THREAT_DETECTION_TLS_CA_BUNDLE"),
			ClientCertPath: os.Getenv("THREAT_DETECTION_CLIENT_CERT"),
			ClientKeyPath:  os.Getenv("THREAT_DETECTION_CLIENT_KEY"),
		},
		Auth0: Auth0{
			JWKSURL:     os.Getenv("AUTH0_JWKS_URL"),
			Issuer:      os.Getenv("AUTH0_ISSUER"),
			Audience:    os.Getenv("AUTH0_AUDIENCE"),
			CacheMinTTL: jwksCacheMinTTL(),
		},
	}

	required := map[string]string{
		"HALDEN_INTERNAL_TOKEN_PRIVATE_KEY": cfg.InternalTokenPrivateKey,
		"AUTH0_JWKS_URL":                    cfg.Auth0.JWKSURL,
		"AUTH0_ISSUER":                      cfg.Auth0.Issuer,
		"AUTH0_AUDIENCE":                    cfg.Auth0.Audience,
	}
	for name, value := range required {
		if value == "" {
			return Config{}, fmt.Errorf("config: %s is not set", name)
		}
	}
	return cfg, nil
}

// jwksCacheMinTTL reads JWKS_CACHE_MIN_TTL_SECONDS, falling back to the
// package default when it is unset or unreadable. An unparseable value is not
// an error worth refusing to start over, but it must not silently become zero
// either — zero removes the floor entirely.
func jwksCacheMinTTL() time.Duration {
	raw := os.Getenv("JWKS_CACHE_MIN_TTL_SECONDS")
	if raw == "" {
		return auth.DefaultJWKSMinRefreshInterval
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return auth.DefaultJWKSMinRefreshInterval
	}
	// Clamp rather than reject. A value above the ceiling is a misconfiguration
	// that would leave a revoked key trusted for as long as it names, and
	// refusing to start over it trades a security problem for an outage. The
	// clamp is logged so it is visible rather than mysterious.
	interval := time.Duration(seconds) * time.Second
	if interval > auth.MaxJWKSMinRefreshInterval {
		slog.Warn("JWKS_CACHE_MIN_TTL_SECONDS above the permitted ceiling; clamping",
			"requested", interval.String(),
			"applied", auth.MaxJWKSMinRefreshInterval.String())
		return auth.MaxJWKSMinRefreshInterval
	}
	return interval
}

func valueOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
