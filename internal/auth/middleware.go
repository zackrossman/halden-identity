package auth

import (
	"log/slog"
	"net/http"
	"strings"
)

// Middleware rejects requests without a valid access token and puts the
// resulting claims on the request context.
func Middleware(v *Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				unauthorized(w)
				return
			}

			claims, err := v.Validate(r.Context(), raw)
			if err != nil {
				slog.InfoContext(r.Context(), "rejected access token", "error", err, "path", r.URL.Path)
				unauthorized(w)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || value == "" {
		return "", false
	}
	return value, true
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="halden"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
