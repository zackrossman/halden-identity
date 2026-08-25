// Package downstream mints the short-lived tokens halden-identity presents when
// it calls internal Halden services.
package downstream

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// Minter signs the short-lived tokens presented to internal services.
//
// It signs one of two ways. With an RSA private key it uses RS256, and the
// verifying service holds only the matching public key, so reading that
// service's configuration does not let anyone mint a token. Without one it
// falls back to HS256 over the shared secret, where both services hold the
// same key and either of them can mint. RS256 is the destination; the fallback
// exists so this service can be deployed before a keypair is provisioned.
type Minter struct {
	secret     []byte
	privateKey *rsa.PrivateKey
}

// NewMinter builds a Minter that signs with the shared internal secret.
func NewMinter(secret string) *Minter {
	return &Minter{secret: []byte(secret)}
}

// NewRS256Minter builds a Minter that signs with a PEM-encoded RSA private key.
func NewRS256Minter(privateKeyPEM string) (*Minter, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("downstream: private key is not PEM encoded")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// PKCS#1 is what `openssl genrsa` writes without -outform pkcs8, so a
		// key generated the obvious way still loads.
		rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if pkcs1Err != nil {
			return nil, fmt.Errorf("downstream: parse private key: %w", err)
		}
		return &Minter{privateKey: rsaKey}, nil
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("downstream: private key is %T, want an RSA key", parsed)
	}
	return &Minter{privateKey: rsaKey}, nil
}

// NewMinterFromConfig returns an RS256 minter when a private key is configured,
// and the shared-secret minter otherwise.
func NewMinterFromConfig(secret, privateKeyPEM string) (*Minter, error) {
	if privateKeyPEM == "" {
		return NewMinter(secret), nil
	}
	return NewRS256Minter(privateKeyPEM)
}

// Algorithm reports which signature algorithm this minter signs with.
func (m *Minter) Algorithm() jwa.SignatureAlgorithm {
	if m.privateKey != nil {
		return jwa.RS256
	}
	return jwa.HS256
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

	var key jwt.SignEncryptParseOption
	if m.privateKey != nil {
		key = jwt.WithKey(jwa.RS256, m.privateKey)
	} else {
		key = jwt.WithKey(jwa.HS256, m.secret)
	}
	signed, err := jwt.Sign(tok, key)
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
