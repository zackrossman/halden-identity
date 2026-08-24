package downstream

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/zackrossman/halden-identity/internal/auth"
)

const secret = "unit-test-secret"

func parse(t *testing.T, raw string) jwt.Token {
	t.Helper()
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithVerify(true), jwt.WithKey(jwa.HS256, []byte(secret)),
		jwt.WithValidate(true),
		jwt.WithIssuer(tokenIssuer), jwt.WithAudience(tokenAudience),
	)
	if err != nil {
		t.Fatalf("token did not verify: %v", err)
	}
	return tok
}

func TestUserToken_CarriesTenant(t *testing.T) {
	raw, err := NewMinter(secret).UserToken(auth.Claims{Subject: "auth0|nw-1", TenantID: "northwind"})
	if err != nil {
		t.Fatal(err)
	}
	tok := parse(t, raw)
	if got, _ := tok.Get("tenant_id"); got != "northwind" {
		t.Errorf("tenant_id = %v, want northwind", got)
	}
	if tok.Subject() != "auth0|nw-1" {
		t.Errorf("sub = %q, want auth0|nw-1", tok.Subject())
	}
}

func TestPlatformToken_CarriesScope(t *testing.T) {
	raw, err := NewMinter(secret).PlatformToken()
	if err != nil {
		t.Fatal(err)
	}
	tok := parse(t, raw)
	scopes, ok := tok.Get("scopes")
	if !ok {
		t.Fatal("no scopes claim")
	}
	list, ok := scopes.([]any)
	if !ok || len(list) != 1 || list[0] != platformAggregateScope {
		t.Errorf("scopes = %v, want [%s]", scopes, platformAggregateScope)
	}
}

func TestTokens_RejectWrongSecret(t *testing.T) {
	raw, _ := NewMinter(secret).UserToken(auth.Claims{Subject: "s", TenantID: "t"})
	if _, err := jwt.Parse([]byte(raw), jwt.WithVerify(true), jwt.WithKey(jwa.HS256, []byte("wrong"))); err == nil {
		t.Error("token verified under the wrong secret")
	}
}
