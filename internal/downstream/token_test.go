package downstream

import (
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/zackrossman/halden-identity/internal/auth"
)

// testMinter builds an RS256 minter over a keypair generated for this run, and
// returns the public half so a test can verify the way a downstream service
// would — holding nothing but the public key.
func testMinter(t *testing.T) (*Minter, *rsa.PublicKey) {
	t.Helper()
	key, keyPEM := generateKeyPEM(t, true)
	m, err := NewRS256Minter(keyPEM)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	return m, &key.PublicKey
}

func parse(t *testing.T, raw string, verifyKey *rsa.PublicKey) jwt.Token {
	t.Helper()
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithVerify(true), jwt.WithKey(jwa.RS256, verifyKey),
		jwt.WithValidate(true),
		jwt.WithIssuer(tokenIssuer), jwt.WithAudience(tokenAudience),
	)
	if err != nil {
		t.Fatalf("token did not verify: %v", err)
	}
	return tok
}

func TestUserToken_CarriesTenant(t *testing.T) {
	m, pub := testMinter(t)
	raw, err := m.UserToken(auth.Claims{Subject: "auth0|nw-1", TenantID: "northwind"})
	if err != nil {
		t.Fatal(err)
	}
	tok := parse(t, raw, pub)
	if got, _ := tok.Get("tenant_id"); got != "northwind" {
		t.Errorf("tenant_id = %v, want northwind", got)
	}
	if tok.Subject() != "auth0|nw-1" {
		t.Errorf("sub = %q, want auth0|nw-1", tok.Subject())
	}
}

func TestPlatformToken_CarriesScope(t *testing.T) {
	m, pub := testMinter(t)
	raw, err := m.PlatformToken()
	if err != nil {
		t.Fatal(err)
	}
	tok := parse(t, raw, pub)
	scopes, ok := tok.Get("scopes")
	if !ok {
		t.Fatal("no scopes claim")
	}
	list, ok := scopes.([]any)
	if !ok || len(list) != 1 || list[0] != platformAggregateScope {
		t.Errorf("scopes = %v, want [%s]", scopes, platformAggregateScope)
	}
}

func TestTokens_DoNotVerifyUnderAnotherKey(t *testing.T) {
	m, _ := testMinter(t)
	_, otherPub := testMinter(t)

	raw, err := m.UserToken(auth.Claims{Subject: "s", TenantID: "t"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := jwt.Parse([]byte(raw), jwt.WithVerify(true), jwt.WithKey(jwa.RS256, otherPub)); err == nil {
		t.Error("token verified under an unrelated public key")
	}
}

func TestTokens_AreSignedRS256(t *testing.T) {
	m, _ := testMinter(t)
	if m.Algorithm() != jwa.RS256 {
		t.Errorf("algorithm = %v, want RS256", m.Algorithm())
	}
}
