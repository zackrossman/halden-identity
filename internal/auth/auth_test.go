package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	testIssuer   = "https://halden.eu.auth0.com/"
	testAudience = "https://api.halden.io"
	testKeyID    = "halden-test-key"
)

// staticKeys serves a fixed key set in place of the Auth0 JWKS endpoint.
type staticKeys struct{ set jwk.Set }

func (s staticKeys) Keys(context.Context) (jwk.Set, error) { return s.set, nil }

// signer holds a throwaway RSA key pair generated for this test run.
type signer struct {
	private jwk.Key
	public  jwk.Set
}

func newSigner(t *testing.T) signer {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	private, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("private jwk: %v", err)
	}
	public, err := jwk.FromRaw(raw.Public())
	if err != nil {
		t.Fatalf("public jwk: %v", err)
	}
	for _, key := range []jwk.Key{private, public} {
		if err := key.Set(jwk.KeyIDKey, testKeyID); err != nil {
			t.Fatalf("set kid: %v", err)
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
			t.Fatalf("set alg: %v", err)
		}
	}

	set := jwk.NewSet()
	if err := set.AddKey(public); err != nil {
		t.Fatalf("add key: %v", err)
	}
	return signer{private: private, public: set}
}

// token builds a signed access token from the given claims.
func (s signer) token(t *testing.T, build func(*jwt.Builder) *jwt.Builder) string {
	t.Helper()

	b := jwt.NewBuilder().
		Issuer(testIssuer).
		Audience([]string{testAudience}).
		Subject("auth0|nw-001").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim(TenantClaim, "northwind")
	if build != nil {
		b = build(b)
	}

	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.private))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// stubDirectory admits exactly the pairs it is given.
type stubDirectory map[string]string

func (d stubDirectory) HasMember(tenantID, subject string) bool {
	return d[tenantID] == subject
}

// testDirectory admits the subject and tenant the test signer mints by default.
func testDirectory() stubDirectory { return stubDirectory{"northwind": "auth0|nw-001"} }

func newTestValidator(s signer) *Validator {
	return NewValidator(staticKeys{set: s.public}, testIssuer, testAudience, testDirectory())
}

func TestValidate_AcceptsValidToken(t *testing.T) {
	s := newSigner(t)

	claims, err := newTestValidator(s).Validate(context.Background(), s.token(t, nil))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "auth0|nw-001" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "auth0|nw-001")
	}
	if claims.TenantID != "northwind" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "northwind")
	}
}

func TestValidate_RejectsExpiredToken(t *testing.T) {
	s := newSigner(t)
	raw := s.token(t, func(b *jwt.Builder) *jwt.Builder {
		return b.IssuedAt(time.Now().Add(-2 * time.Hour)).Expiration(time.Now().Add(-time.Hour))
	})

	if _, err := newTestValidator(s).Validate(context.Background(), raw); err == nil {
		t.Fatal("Validate accepted an expired token")
	}
}

func TestValidate_RejectsWrongIssuer(t *testing.T) {
	s := newSigner(t)
	raw := s.token(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Issuer("https://attacker.example/")
	})

	if _, err := newTestValidator(s).Validate(context.Background(), raw); err == nil {
		t.Fatal("Validate accepted a token from the wrong issuer")
	}
}

func TestValidate_RejectsWrongAudience(t *testing.T) {
	s := newSigner(t)
	raw := s.token(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Audience([]string{"https://api.other.example"})
	})

	if _, err := newTestValidator(s).Validate(context.Background(), raw); err == nil {
		t.Fatal("Validate accepted a token for the wrong audience")
	}
}

func TestValidate_RejectsTokenSignedByUnknownKey(t *testing.T) {
	trusted := newSigner(t)
	attacker := newSigner(t)

	validator := NewValidator(staticKeys{set: trusted.public}, testIssuer, testAudience, testDirectory())
	if _, err := validator.Validate(context.Background(), attacker.token(t, nil)); err == nil {
		t.Fatal("Validate accepted a token signed by an unknown key")
	}
}

func TestValidate_RejectsMissingTenantClaim(t *testing.T) {
	s := newSigner(t)

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Audience([]string{testAudience}).
		Subject("auth0|nw-001").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.private))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = newTestValidator(s).Validate(context.Background(), string(signed))
	if !errors.Is(err, ErrMissingTenant) {
		t.Fatalf("err = %v, want %v", err, ErrMissingTenant)
	}
}
