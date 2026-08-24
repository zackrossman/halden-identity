package auth

import "context"

type contextKey struct{}

// WithClaims returns a context carrying the validated claims.
func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, contextKey{}, claims)
}

// FromContext returns the validated claims placed on the context by Middleware.
func FromContext(ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(contextKey{}).(Claims)
	return claims, ok
}
