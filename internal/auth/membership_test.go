package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// A validated Auth0 token proves Auth0 issued it. It does not prove the
// subject belongs to the tenant the token names — that claim comes from an
// Auth0 rule, and a misconfiguration or a compromise there points a caller at
// another tenant's data with a perfectly valid signature. Every downstream
// read is scoped by this claim, so it is checked against the directory.

func TestValidate_RefusesASubjectNotInTheClaimedTenant(t *testing.T) {
	s := newSigner(t)
	// The signer mints sub=auth0|nw-001 with tenant=northwind. The directory
	// says that subject belongs to contoso instead.
	validator := NewValidator(
		staticKeys{set: s.public}, testIssuer, testAudience,
		stubDirectory{"contoso": "auth0|nw-001"},
	)

	_, err := validator.Validate(context.Background(), s.token(t, nil))

	if !errors.Is(err, ErrNotTenantMember) {
		t.Fatalf("err = %v, want %v", err, ErrNotTenantMember)
	}
}

func TestValidate_RefusesAnUnknownSubject(t *testing.T) {
	s := newSigner(t)
	validator := NewValidator(
		staticKeys{set: s.public}, testIssuer, testAudience,
		stubDirectory{"northwind": "auth0|somebody-else"},
	)

	_, err := validator.Validate(context.Background(), s.token(t, nil))

	if !errors.Is(err, ErrNotTenantMember) {
		t.Fatalf("err = %v, want %v", err, ErrNotTenantMember)
	}
}

func TestValidate_RefusedMembershipReturnsNoClaims(t *testing.T) {
	// The refusal must not leak a usable tenant scope to the caller.
	s := newSigner(t)
	validator := NewValidator(
		staticKeys{set: s.public}, testIssuer, testAudience, stubDirectory{},
	)

	claims, err := validator.Validate(context.Background(), s.token(t, nil))

	if err == nil {
		t.Fatal("expected a refusal")
	}
	if claims.TenantID != "" || claims.Subject != "" {
		t.Errorf("claims = %+v, want zero on refusal", claims)
	}
}

func TestValidate_TheAttackThisStops(t *testing.T) {
	// A token whose tenant claim was tampered with at the source: correctly
	// signed, well-formed tenant id, but naming a tenant the subject has no
	// business in. Format validation passes it; membership does not.
	s := newSigner(t)
	validator := NewValidator(
		staticKeys{set: s.public}, testIssuer, testAudience,
		stubDirectory{"northwind": "auth0|nw-001"},
	)

	signed := s.token(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Claim(TenantClaim, "contoso")
	})

	if _, err := validator.Validate(context.Background(), signed); !errors.Is(err, ErrNotTenantMember) {
		t.Fatalf("a valid token claiming another tenant was accepted: err = %v", err)
	}
}

func TestValidate_RefusesWhenNoDirectoryIsConfigured(t *testing.T) {
	// Fail closed: a Validator that cannot answer the membership question must
	// not admit the claim unchecked.
	s := newSigner(t)
	validator := NewValidator(staticKeys{set: s.public}, testIssuer, testAudience, nil)

	_, err := validator.Validate(context.Background(), s.token(t, nil))

	if !errors.Is(err, ErrNoDirectory) {
		t.Fatalf("err = %v, want %v", err, ErrNoDirectory)
	}
}

func TestValidate_AcceptsAMemberOfTheClaimedTenant(t *testing.T) {
	s := newSigner(t)
	validator := newTestValidator(s)

	claims, err := validator.Validate(context.Background(), s.token(t, nil))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.TenantID != "northwind" || claims.Subject != "auth0|nw-001" {
		t.Errorf("claims = %+v", claims)
	}
}
