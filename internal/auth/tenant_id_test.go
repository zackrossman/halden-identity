package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// A validated Auth0 token proves who issued it. It does not prove the tenant
// claim is a safe value, and downstream services use that value as a database
// filter and as a directory name in the artifact store.
var malformedTenantIDs = map[string]string{
	"parent traversal":   "../contoso",
	"bare dots":          "..",
	"deep traversal":     "../../etc/passwd",
	"forward separator":  "north/wind",
	"backward separator": "north\\wind",
	"absolute path":      "/absolute",
	"null byte":          "northwind\x00",
	"space":              "north wind",
	"percent encoded":    "%2e%2e%2f",
	"dot":                "north.wind",
	"semicolon":          "north;wind",
	"sql fragment":       "'; DROP TABLE detections--",
	"newline":            "northwind\ncontoso",
}

func TestValidate_RejectsMalformedTenantClaim(t *testing.T) {
	s := newSigner(t)
	validator := newTestValidator(s)

	for name, tenant := range malformedTenantIDs {
		t.Run(name, func(t *testing.T) {
			signed := s.token(t, func(b *jwt.Builder) *jwt.Builder {
				return b.Claim(TenantClaim, tenant)
			})

			_, err := validator.Validate(context.Background(), signed)
			if !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("err = %v, want %v", err, ErrInvalidTenant)
			}
		})
	}
}

func TestValidate_AcceptsWellFormedTenantClaims(t *testing.T) {
	s := newSigner(t)

	for _, tenant := range []string{"northwind", "contoso", "acme-corp", "acme_corp", "T3nant"} {
		t.Run(tenant, func(t *testing.T) {
			// The directory must list the pair; this test is about the format
			// check, not membership.
			validator := NewValidator(
				staticKeys{set: s.public}, testIssuer, testAudience,
				stubDirectory{tenant: "auth0|nw-001"},
			)
			signed := s.token(t, func(b *jwt.Builder) *jwt.Builder {
				return b.Claim(TenantClaim, tenant)
			})

			claims, err := validator.Validate(context.Background(), signed)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if claims.TenantID != tenant {
				t.Errorf("TenantID = %q, want %q", claims.TenantID, tenant)
			}
		})
	}
}

func TestValidate_MalformedTenantIsNotSilentlyPassedOn(t *testing.T) {
	// The failure must be a refusal, not a claim that reaches a downstream
	// query filter or path segment.
	s := newSigner(t)
	signed := s.token(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Claim(TenantClaim, "../contoso")
	})

	claims, err := newTestValidator(s).Validate(context.Background(), signed)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if claims.TenantID != "" {
		t.Errorf("TenantID = %q, want empty on refusal", claims.TenantID)
	}
}

func TestTenantIDPattern_IsAnchoredAtBothEnds(t *testing.T) {
	// An unanchored pattern would match the trailing segment of "../contoso".
	for _, bad := range []string{"../contoso", "contoso/..", "contoso\nnorthwind"} {
		if tenantIDPattern.MatchString(bad) {
			t.Errorf("pattern matched %q", bad)
		}
	}
}
