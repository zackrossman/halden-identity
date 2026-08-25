// Package auth validates Auth0-issued access tokens and carries the resulting
// claims on the request context.
package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TenantClaim is the namespaced Auth0 claim carrying the caller's tenant.
const TenantClaim = "https://halden.io/tenant_id"

// ErrMissingTenant is returned when a token validates but carries no tenant claim.
var ErrMissingTenant = errors.New("auth: token has no tenant claim")

// ErrInvalidTenant is returned when the tenant claim is present but is not a
// well-formed tenant id.
var ErrInvalidTenant = errors.New("auth: token has a malformed tenant claim")

// The shape a tenant id must have. A validated Auth0 token proves who issued
// it, not that this claim is safe to use, and downstream services take the
// value as a database filter and as a path segment in the artifact store. A
// claim carrying a separator or `..` escapes its own tenant there, so the
// gateway refuses it here rather than passing it on.
var tenantIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Claims is the authenticated identity taken from a validated access token.
type Claims struct {
	Subject  string
	TenantID string
}

// KeySource supplies the public keys a token may be signed with.
type KeySource interface {
	Keys(ctx context.Context) (jwk.Set, error)
}

// Validator checks access tokens against the Auth0 JWKS, issuer and audience.
type Validator struct {
	keys     KeySource
	issuer   string
	audience string
}

// NewValidator builds a Validator over the given key source.
func NewValidator(keys KeySource, issuer, audience string) *Validator {
	return &Validator{keys: keys, issuer: issuer, audience: audience}
}

// Validate parses and verifies a raw bearer token and returns its claims.
func (v *Validator) Validate(ctx context.Context, raw string) (Claims, error) {
	set, err := v.keys.Keys(ctx)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: fetch keys: %w", err)
	}

	token, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: invalid token: %w", err)
	}

	claim, ok := token.Get(TenantClaim)
	if !ok {
		return Claims{}, ErrMissingTenant
	}
	tenant, ok := claim.(string)
	if !ok || tenant == "" {
		return Claims{}, ErrMissingTenant
	}
	if !tenantIDPattern.MatchString(tenant) {
		return Claims{}, fmt.Errorf("%w: %q", ErrInvalidTenant, tenant)
	}

	return Claims{Subject: token.Subject(), TenantID: tenant}, nil
}

// JWKSCache fetches and caches the Auth0 JWKS, refreshing it in the background.
type JWKSCache struct {
	cache *jwk.Cache
	url   string
}

// DefaultJWKSMinRefreshInterval is how long a revoked Auth0 signing key can
// still be trusted when Auth0 sends no cache headers of its own.
//
// The interval is the floor on how often the key set is refetched, so it is
// also the ceiling on the window in which a key Auth0 has already retired
// still validates tokens here. It was 15 minutes, which is a long time to keep
// honouring a key that was rotated because it leaked. Five minutes trades a
// few more requests to the JWKS endpoint — one per instance per interval,
// against a CDN-backed URL — for a shorter window.
const DefaultJWKSMinRefreshInterval = 5 * time.Minute

// NewJWKSCache registers the JWKS endpoint with a refreshing cache.
//
// A minRefresh of zero or less falls back to the default rather than being
// passed through: jwx treats a zero interval as "no floor", which would leave
// the window governed entirely by whatever Auth0's cache headers happen to
// say, and a misread config value should not quietly change that.
func NewJWKSCache(ctx context.Context, url string, minRefresh time.Duration) (*JWKSCache, error) {
	if minRefresh <= 0 {
		minRefresh = DefaultJWKSMinRefreshInterval
	}
	cache := jwk.NewCache(ctx)
	if err := cache.Register(url, jwk.WithMinRefreshInterval(minRefresh)); err != nil {
		return nil, fmt.Errorf("auth: register jwks: %w", err)
	}
	return &JWKSCache{cache: cache, url: url}, nil
}

// Keys returns the current key set.
func (c *JWKSCache) Keys(ctx context.Context) (jwk.Set, error) {
	return c.cache.Get(ctx, c.url)
}
