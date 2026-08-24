// Package auth validates Auth0-issued access tokens and carries the resulting
// claims on the request context.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TenantClaim is the namespaced Auth0 claim carrying the caller's tenant.
const TenantClaim = "https://halden.io/tenant_id"

// ErrMissingTenant is returned when a token validates but carries no tenant claim.
var ErrMissingTenant = errors.New("auth: token has no tenant claim")

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

	return Claims{Subject: token.Subject(), TenantID: tenant}, nil
}

// JWKSCache fetches and caches the Auth0 JWKS, refreshing it in the background.
type JWKSCache struct {
	cache *jwk.Cache
	url   string
}

// NewJWKSCache registers the JWKS endpoint with a refreshing cache.
func NewJWKSCache(ctx context.Context, url string) (*JWKSCache, error) {
	cache := jwk.NewCache(ctx)
	if err := cache.Register(url, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
		return nil, fmt.Errorf("auth: register jwks: %w", err)
	}
	return &JWKSCache{cache: cache, url: url}, nil
}

// Keys returns the current key set.
func (c *JWKSCache) Keys(ctx context.Context) (jwk.Set, error) {
	return c.cache.Get(ctx, c.url)
}
