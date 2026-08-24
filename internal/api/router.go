// Package api wires the HTTP routes of halden-identity.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/zackrossman/halden-identity/internal/auth"
	"github.com/zackrossman/halden-identity/internal/users"
)

// NewRouter returns the service handler. /healthz is open; everything under
// /v1 requires a valid Auth0 access token.
func NewRouter(v *auth.Validator, store *users.Store, threatScans http.Handler) http.Handler {
	protected := http.NewServeMux()
	protected.HandleFunc("GET /v1/users/me", currentUser(store))
	protected.HandleFunc("GET /v1/users", listUsers(store))
	protected.Handle("GET /v1/threat-scans", threatScans)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(r, w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("/v1/", auth.Middleware(v)(protected))
	return mux
}

func currentUser(store *users.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.FromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		user, found := store.Find(claims.TenantID, claims.Subject)
		if !found {
			// Auth0 is the source of truth for users, so a token can legitimately
			// name a subject the local directory has not seen yet.
			user = users.User{Subject: claims.Subject, TenantID: claims.TenantID}
		}
		writeJSON(r, w, http.StatusOK, user)
	}
}

func listUsers(store *users.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.FromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(r, w, http.StatusOK, map[string]any{
			"tenant_id": claims.TenantID,
			"users":     store.ListByTenant(claims.TenantID),
		})
	}
}

func writeJSON(r *http.Request, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.WarnContext(r.Context(), "write response", "error", err)
	}
}
