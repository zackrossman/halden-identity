// Package downstream mints the short-lived tokens halden-identity presents when
// it calls internal Halden services.
package downstream

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
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
// It signs RS256 with an RSA private key that stays in this service. The
// verifying service holds only the matching public key, so reading that
// service's configuration, environment or pod does not let anyone mint a
// token. There is no symmetric path: a shared secret would put a minting key
// in every service that only needs to verify.
type Minter struct {
	privateKey *rsa.PrivateKey
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

// Algorithm reports the signature algorithm this minter signs with.
func (m *Minter) Algorithm() jwa.SignatureAlgorithm { return jwa.RS256 }

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

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, m.privateKey))
	if err != nil {
		return "", fmt.Errorf("downstream: sign token: %w", err)
	}
	return string(signed), nil
}

// UserToken mints a downstream token that carries the signed-in customer's
// tenant, taken from the validated access token.
func (m *Minter) UserToken(claims auth.Claims) (string, error) {
	signed, err := m.sign(func(b *jwt.Builder) *jwt.Builder {
		return b.Subject(claims.Subject).Claim("tenant_id", claims.TenantID)
	})
	if err != nil {
		return "", err
	}
	recordMinted("user", claims.Subject, claims.TenantID, nil)
	return signed, nil
}

// PlatformToken mints a downstream token for the platform's own scheduled work,
// which runs with no signed-in customer.
func (m *Minter) PlatformToken() (string, error) {
	signed, err := m.sign(func(b *jwt.Builder) *jwt.Builder {
		return b.Subject("halden-identity/jobs").
			Claim("scopes", []string{platformAggregateScope})
	})
	if err != nil {
		return "", err
	}
	recordMinted("platform", "halden-identity/jobs", "", []string{platformAggregateScope})
	return signed, nil
}

// recordMinted logs the issuance of a downstream credential.
//
// Every token this service mints authorises a read somewhere else, so an
// investigation that can see which reads happened but not which credentials
// were issued can only work backwards. The estate-wide platform token matters
// most: it is the one that crosses every tenant boundary, and its issuance
// should be countable.
//
// The token is never logged. Its claims identify what was granted; the token
// itself would be a usable credential sitting in a log.
func recordMinted(kind, subject, tenant string, scopes []string) {
	attrs := []any{
		"kind", kind,
		"subject", subject,
		"ttl_seconds", int(tokenTTL.Seconds()),
		"audience", tokenAudience,
	}
	if tenant != "" {
		attrs = append(attrs, "tenant", tenant)
	}
	if len(scopes) > 0 {
		attrs = append(attrs, "scopes", scopes)
	}
	slog.Info("downstream token minted", attrs...)
}
