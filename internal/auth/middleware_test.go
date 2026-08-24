package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_RejectsRequestsWithoutBearerToken(t *testing.T) {
	s := newSigner(t)
	handler := Middleware(newTestValidator(s))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler ran for an unauthenticated request")
	}))

	for name, header := range map[string]string{
		"missing":      "",
		"wrong scheme": "Basic abc",
		"empty token":  "Bearer ",
		"garbage":      "Bearer not-a-jwt",
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
			if header != "" {
				r.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestMiddleware_PutsClaimsOnContext(t *testing.T) {
	s := newSigner(t)

	var seen Claims
	handler := Middleware(newTestValidator(s))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := FromContext(r.Context())
		if !ok {
			t.Fatal("no claims on request context")
		}
		seen = claims
	}))

	r := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	r.Header.Set("Authorization", "Bearer "+s.token(t, nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if seen.TenantID != "northwind" || seen.Subject != "auth0|nw-001" {
		t.Fatalf("claims = %+v, want subject auth0|nw-001 in tenant northwind", seen)
	}
}
