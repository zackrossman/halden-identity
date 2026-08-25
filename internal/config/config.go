// Package config loads the service settings from the environment.
package config

import (
	"fmt"
	"os"
	"strings"
)

const defaultThreatDetectionURL = "http://halden-threat-detection.halden.svc.cluster.local:8000"

// Auth0 holds the settings used to validate incoming access tokens.
type Auth0 struct {
	JWKSURL  string
	Issuer   string
	Audience string
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
	Auth0                   Auth0
}

// Load reads the configuration from the environment. Every secret and endpoint
// comes from the environment; nothing is baked into the binary.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:              valueOr("HALDEN_LISTEN_ADDR", ":8080"),
		InternalTokenPrivateKey: os.Getenv("HALDEN_INTERNAL_TOKEN_PRIVATE_KEY"),
		ThreatDetectionURL:      strings.TrimRight(valueOr("THREAT_DETECTION_URL", defaultThreatDetectionURL), "/"),
		Auth0: Auth0{
			JWKSURL:  os.Getenv("AUTH0_JWKS_URL"),
			Issuer:   os.Getenv("AUTH0_ISSUER"),
			Audience: os.Getenv("AUTH0_AUDIENCE"),
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

func valueOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
