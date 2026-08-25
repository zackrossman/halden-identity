package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/zackrossman/halden-identity/internal/auth"
	"github.com/zackrossman/halden-identity/internal/downstream"
)

// capture stands up a stub halden-threat-detection and returns a proxy pointed
// at it, plus the request the stub last saw.
type capture struct {
	proxy *ThreatScans
	got   *http.Request
}

func newCapture(t *testing.T) *capture {
	t.Helper()
	c := &capture{}
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.got = r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(downstream.Close)
	c.proxy = NewThreatScans(downstream.URL, minter())
	return c
}

// testKeyPEM is the signing key for this package's tests, generated once per
// run so no key material is checked in.
var testKeyPEM, testPublicKey = func() (string, *rsa.PublicKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(pemBytes), &key.PublicKey
}()

func minter() Minter {
	m, err := downstream.NewRS256Minter(testKeyPEM)
	if err != nil {
		panic(err)
	}
	return m
}

func authed(r *http.Request, tenant, subject string) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), auth.Claims{Subject: subject, TenantID: tenant}))
}

// bearerClaims verifies the Authorization bearer against the shared secret and
// returns its claims.
func bearerClaims(t *testing.T, r *http.Request) jwt.Token {
	t.Helper()
	h := r.Header.Get("Authorization")
	if len(h) < 8 || h[:7] != "Bearer " {
		t.Fatalf("missing bearer token, got %q", h)
	}
	tok, err := jwt.Parse([]byte(h[7:]), jwt.WithVerify(true), jwt.WithKey(jwa.RS256, testPublicKey))
	if err != nil {
		t.Fatalf("downstream token did not verify: %v", err)
	}
	return tok
}

func TestList_SendsUserTenantToken(t *testing.T) {
	c := newCapture(t)
	rec := httptest.NewRecorder()
	c.proxy.List(rec, authed(httptest.NewRequest(http.MethodGet, "/v1/threat-scans", nil), "northwind", "auth0|nw-1"))

	if c.got == nil {
		t.Fatalf("downstream received no request (status %d)", rec.Code)
	}
	tok := bearerClaims(t, c.got)
	tenant, _ := tok.Get("tenant_id")
	if tenant != "northwind" {
		t.Errorf("tenant_id = %v, want northwind", tenant)
	}
}

func TestSummary_SendsVerifiableToken(t *testing.T) {
	c := newCapture(t)
	rec := httptest.NewRecorder()
	c.proxy.Summary(rec, authed(httptest.NewRequest(http.MethodGet, "/v1/threat-scans/summary", nil), "northwind", "auth0|nw-1"))

	if c.got == nil {
		t.Fatalf("downstream received no request (status %d)", rec.Code)
	}
	// The summary call presents a valid, signed downstream token.
	bearerClaims(t, c.got)
}

func TestList_RequiresClaims(t *testing.T) {
	c := newCapture(t)
	rec := httptest.NewRecorder()
	c.proxy.List(rec, httptest.NewRequest(http.MethodGet, "/v1/threat-scans", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
