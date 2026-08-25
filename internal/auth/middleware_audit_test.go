package auth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func captureMiddlewareLogs(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	fn()

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		records = append(records, record)
	}
	return records
}

func findRecord(records []map[string]any, msg string) (map[string]any, bool) {
	for _, r := range records {
		if r["msg"] == msg {
			return r, true
		}
	}
	return nil, false
}

// Recording only rejections answers "who was turned away" and not "who got
// in", which is where an investigation actually starts.
func TestMiddleware_RecordsAnAcceptedToken(t *testing.T) {
	s := newSigner(t)
	handler := Middleware(newTestValidator(s))(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	))
	signed := s.token(t, nil)

	records := captureMiddlewareLogs(t, func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	record, ok := findRecord(records, "accepted access token")
	if !ok {
		t.Fatal("no record for the accepted token")
	}
	if record["subject"] != "auth0|nw-001" {
		t.Errorf("subject = %v", record["subject"])
	}
	if record["tenant"] != "northwind" {
		t.Errorf("tenant = %v", record["tenant"])
	}
	if record["path"] != "/v1/users/me" {
		t.Errorf("path = %v", record["path"])
	}
}

func TestMiddleware_AcceptedTokenNeverAppearsInTheLog(t *testing.T) {
	s := newSigner(t)
	handler := Middleware(newTestValidator(s))(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	))
	signed := s.token(t, nil)

	records := captureMiddlewareLogs(t, func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	})

	rendered, _ := json.Marshal(records)
	if bytes.Contains(rendered, []byte(signed)) {
		t.Fatal("the access token appears in the log")
	}
	parts := strings.Split(signed, ".")
	if bytes.Contains(rendered, []byte(parts[len(parts)-1])) {
		t.Fatal("the token signature appears in the log")
	}
}

func TestMiddleware_RefusedTokenIsNotRecordedAsAccepted(t *testing.T) {
	// The two records must not be confusable; a refusal counted as an
	// acceptance would make the log worse than none.
	s := newSigner(t)
	other := newSigner(t)
	handler := Middleware(newTestValidator(s))(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	))

	records := captureMiddlewareLogs(t, func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+other.token(t, nil))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	if _, ok := findRecord(records, "accepted access token"); ok {
		t.Fatal("a refused token was recorded as accepted")
	}
	if _, ok := findRecord(records, "rejected access token"); !ok {
		t.Fatal("the refusal was not recorded")
	}
}
