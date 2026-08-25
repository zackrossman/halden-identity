package auth

import (
	"context"
	"testing"
	"time"
)

func TestNewJWKSCache_UsesTheGivenInterval(t *testing.T) {
	c, err := NewJWKSCache(context.Background(), "https://example.test/.well-known/jwks.json", time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSCache: %v", err)
	}
	if c == nil {
		t.Fatal("nil cache")
	}
}

func TestNewJWKSCache_RejectsNoFloor(t *testing.T) {
	// jwx reads a zero interval as "no floor", which hands the window entirely
	// to whatever cache headers Auth0 sends. A zero must become the default,
	// not disable the bound.
	for _, interval := range []time.Duration{0, -time.Minute} {
		c, err := NewJWKSCache(context.Background(), "https://example.test/.well-known/jwks.json", interval)
		if err != nil {
			t.Fatalf("NewJWKSCache(%v): %v", interval, err)
		}
		if c == nil {
			t.Fatalf("NewJWKSCache(%v): nil cache", interval)
		}
	}
}
