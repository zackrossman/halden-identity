// Package downstream mints the short-lived tokens halden-identity presents when
// it calls internal Halden services.
package downstream

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/zackrossman/halden-identity/internal/auth"
)

const (
	tokenIssuer   = "halden-identity"
	tokenAudience = "halden-threat-detection"
	tokenTTL      = 60 * time.Second

	// Scope requested for the platform's scheduled reporting work.
	platformAggregateScope = "platform:aggregate"
)

// Minter signs downstream tokens with the shared internal secret.
type Minter struct {
	secret []byte
}

// NewMinter builds a Minter over the internal token secret.
func NewMinter(secret string) *Minter {
	return &Minter{secret: []byte(secret)}
}

func (m *Minter) sign(build func(b *jwt.Builder) *jwt.Builder) (string, error) {
	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(tokenIssuer).
		Audience([]string{tokenAudience}).
		IssuedAt(now).
		Expiration(now.Add(tokenTTL))
	tok, err := build(b).Build()
	if err != nil {
		return "", fmt.Errorf("downstream: build token: %w", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, m.secret))
	if err != nil {
		return "", fmt.Errorf("downstream: sign token: %w", err)
	}
	return string(signed), nil
}

// UserToken mints a downstream token that carries the signed-in customer's
// tenant, taken from the validated access token.
func (m *Minter) UserToken(claims auth.Claims) (string, error) {
	return m.sign(func(b *jwt.Builder) *jwt.Builder {
		return b.Subject(claims.Subject).Claim("tenant_id", claims.TenantID)
	})
}

// PlatformToken mints a downstream token for the platform's own scheduled work,
// which runs with no signed-in customer.
func (m *Minter) PlatformToken() (string, error) {
	return m.sign(func(b *jwt.Builder) *jwt.Builder {
		return b.Subject("halden-identity/jobs").
			Claim("scopes", []string{platformAggregateScope})
	})
}
