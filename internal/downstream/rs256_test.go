package downstream

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/zackrossman/halden-identity/internal/auth"
)

// generateKeyPEM returns a fresh RSA private key in the requested encoding, so
// no key material is checked in.
func generateKeyPEM(t *testing.T, pkcs8 bool) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var der []byte
	blockType := "RSA PRIVATE KEY"
	if pkcs8 {
		der, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal pkcs8: %v", err)
		}
		blockType = "PRIVATE KEY"
	} else {
		der = x509.MarshalPKCS1PrivateKey(key)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func TestRS256Minter_SignsWithRS256(t *testing.T) {
	key, keyPEM := generateKeyPEM(t, true)
	m, err := NewRS256Minter(keyPEM)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	if m.Algorithm() != jwa.RS256 {
		t.Errorf("algorithm = %v, want RS256", m.Algorithm())
	}

	signed, err := m.UserToken(auth.Claims{Subject: "auth0|nw-1", TenantID: "northwind"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The public half alone must verify it.
	tok, err := jwt.Parse([]byte(signed), jwt.WithVerify(true), jwt.WithKey(jwa.RS256, &key.PublicKey))
	if err != nil {
		t.Fatalf("verify with public key: %v", err)
	}
	tenant, _ := tok.Get("tenant_id")
	if tenant != "northwind" {
		t.Errorf("tenant_id = %v, want northwind", tenant)
	}
}

func TestRS256Minter_AcceptsPKCS1Keys(t *testing.T) {
	// `openssl genrsa` writes PKCS#1 by default; a key made the obvious way
	// must load rather than being rejected as malformed.
	_, keyPEM := generateKeyPEM(t, false)

	m, err := NewRS256Minter(keyPEM)
	if err != nil {
		t.Fatalf("new minter from pkcs1: %v", err)
	}
	if m.Algorithm() != jwa.RS256 {
		t.Errorf("algorithm = %v, want RS256", m.Algorithm())
	}
}

func TestRS256Minter_TokenDoesNotVerifyAgainstTheSharedSecret(t *testing.T) {
	// The point of the migration: a service holding only the old shared secret
	// gains nothing from an RS256 token.
	_, keyPEM := generateKeyPEM(t, true)
	m, err := NewRS256Minter(keyPEM)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	signed, err := m.PlatformToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, err := jwt.Parse([]byte(signed), jwt.WithVerify(true), jwt.WithKey(jwa.HS256, []byte(secret))); err == nil {
		t.Fatal("an RS256 token verified against the shared HMAC secret")
	}
}

func TestNewMinterFromConfig_FallsBackToHS256(t *testing.T) {
	m, err := NewMinterFromConfig(secret, "")
	if err != nil {
		t.Fatalf("from config: %v", err)
	}
	if m.Algorithm() != jwa.HS256 {
		t.Errorf("algorithm = %v, want HS256 when no private key is configured", m.Algorithm())
	}

	signed, err := m.UserToken(auth.Claims{Subject: "auth0|nw-1", TenantID: "northwind"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := jwt.Parse([]byte(signed), jwt.WithVerify(true), jwt.WithKey(jwa.HS256, []byte(secret))); err != nil {
		t.Fatalf("fallback token did not verify with the shared secret: %v", err)
	}
}

func TestNewMinterFromConfig_PrefersThePrivateKey(t *testing.T) {
	_, keyPEM := generateKeyPEM(t, true)

	m, err := NewMinterFromConfig(secret, keyPEM)
	if err != nil {
		t.Fatalf("from config: %v", err)
	}
	if m.Algorithm() != jwa.RS256 {
		t.Errorf("algorithm = %v, want RS256 when a private key is configured", m.Algorithm())
	}
}

func TestNewRS256Minter_RejectsGarbage(t *testing.T) {
	for name, input := range map[string]string{
		"not pem":     "definitely-not-a-key",
		"empty":       "",
		"pem, no key": "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRS256Minter(input); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}
