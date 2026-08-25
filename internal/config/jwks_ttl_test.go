package config

import (
	"testing"
	"time"

	"github.com/zackrossman/halden-identity/internal/auth"
)

// The JWKS refresh floor is also the ceiling on how long a key Auth0 has
// already revoked keeps validating tokens here. A misread value must never
// widen that window silently.
func TestJWKSCacheMinTTL(t *testing.T) {
	for name, tc := range map[string]struct {
		env  string
		want time.Duration
	}{
		"unset falls back":       {"", auth.DefaultJWKSMinRefreshInterval},
		"valid seconds":          {"60", time.Minute},
		"valid larger":           {"900", 15 * time.Minute},
		"zero falls back":        {"0", auth.DefaultJWKSMinRefreshInterval},
		"negative falls back":    {"-30", auth.DefaultJWKSMinRefreshInterval},
		"unparseable falls back": {"soon", auth.DefaultJWKSMinRefreshInterval},
		"empty-ish falls back":   {"   ", auth.DefaultJWKSMinRefreshInterval},
		"float falls back":       {"5.5", auth.DefaultJWKSMinRefreshInterval},
		"at the ceiling":         {"900", auth.MaxJWKSMinRefreshInterval},
		"above the ceiling":      {"3600", auth.MaxJWKSMinRefreshInterval},
		"absurd value clamped":   {"999999999", auth.MaxJWKSMinRefreshInterval},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("JWKS_CACHE_MIN_TTL_SECONDS", tc.env)
			if got := jwksCacheMinTTL(); got != tc.want {
				t.Errorf("jwksCacheMinTTL() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultIsShorterThanTheOldFifteenMinutes(t *testing.T) {
	// The finding was that 15 minutes is too long to keep honouring a revoked
	// key. A change that did not shorten it would close nothing.
	if auth.DefaultJWKSMinRefreshInterval >= 15*time.Minute {
		t.Errorf("default = %v, want less than 15m", auth.DefaultJWKSMinRefreshInterval)
	}
}

// A configurable floor is only an improvement while it cannot be configured
// back past where it started. An operator setting a year must not leave a
// revoked Auth0 key trusted for a year.
func TestJWKSCacheMinTTL_NeverExceedsTheCeiling(t *testing.T) {
	for _, raw := range []string{"901", "3600", "86400", "31536000", "999999999"} {
		t.Setenv("JWKS_CACHE_MIN_TTL_SECONDS", raw)
		if got := jwksCacheMinTTL(); got > auth.MaxJWKSMinRefreshInterval {
			t.Errorf("%s: got %v, above the ceiling %v", raw, got, auth.MaxJWKSMinRefreshInterval)
		}
	}
}

func TestCeilingIsNoWorseThanTheOldHardcodedValue(t *testing.T) {
	// The window this control exists to shorten was 15 minutes before it was
	// configurable. No configuration may make it worse than it already was.
	if auth.MaxJWKSMinRefreshInterval > 15*time.Minute {
		t.Errorf("ceiling = %v, want at most 15m", auth.MaxJWKSMinRefreshInterval)
	}
	if auth.DefaultJWKSMinRefreshInterval > auth.MaxJWKSMinRefreshInterval {
		t.Errorf("default %v exceeds ceiling %v",
			auth.DefaultJWKSMinRefreshInterval, auth.MaxJWKSMinRefreshInterval)
	}
}
