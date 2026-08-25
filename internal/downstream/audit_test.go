package downstream

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/zackrossman/halden-identity/internal/auth"
)

// captureLogs swaps the default logger for one writing JSON to a buffer, and
// returns the records produced while fn ran.
func captureLogs(t *testing.T, fn func()) []map[string]any {
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

func only(t *testing.T, records []map[string]any, msg string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, r := range records {
		if r["msg"] == msg {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected one %q record, got %d", msg, len(found))
	}
	return found[0]
}

func TestUserToken_IsRecorded(t *testing.T) {
	m, _ := testMinter(t)
	var signed string

	records := captureLogs(t, func() {
		var err error
		signed, err = m.UserToken(auth.Claims{Subject: "auth0|nw-001", TenantID: "northwind"})
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
	})

	record := only(t, records, "downstream token minted")
	if record["kind"] != "user" {
		t.Errorf("kind = %v, want user", record["kind"])
	}
	if record["subject"] != "auth0|nw-001" {
		t.Errorf("subject = %v", record["subject"])
	}
	if record["tenant"] != "northwind" {
		t.Errorf("tenant = %v", record["tenant"])
	}
	if signed == "" {
		t.Fatal("no token minted")
	}
}

func TestPlatformToken_IsRecordedWithItsScope(t *testing.T) {
	// The estate-wide credential is the one that crosses every tenant
	// boundary, so its issuance must be visible and countable.
	m, _ := testMinter(t)

	records := captureLogs(t, func() {
		if _, err := m.PlatformToken(); err != nil {
			t.Fatalf("mint: %v", err)
		}
	})

	record := only(t, records, "downstream token minted")
	if record["kind"] != "platform" {
		t.Errorf("kind = %v, want platform", record["kind"])
	}
	if record["subject"] != "halden-identity/jobs" {
		t.Errorf("subject = %v", record["subject"])
	}
	scopes, ok := record["scopes"].([]any)
	if !ok || len(scopes) != 1 || scopes[0] != platformAggregateScope {
		t.Errorf("scopes = %v, want [%s]", record["scopes"], platformAggregateScope)
	}
}

func TestMintedTokenNeverAppearsInTheLog(t *testing.T) {
	// The claims identify what was granted. The token itself would be a usable
	// credential sitting in a log.
	m, _ := testMinter(t)
	var signed string

	records := captureLogs(t, func() {
		var err error
		signed, err = m.UserToken(auth.Claims{Subject: "auth0|nw-001", TenantID: "northwind"})
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
	})

	rendered, _ := json.Marshal(records)
	if bytes.Contains(rendered, []byte(signed)) {
		t.Fatal("the minted token appears in the log")
	}
	// Not even the signature segment.
	parts := strings.Split(signed, ".")
	if bytes.Contains(rendered, []byte(parts[len(parts)-1])) {
		t.Fatal("the token signature appears in the log")
	}
}

func TestPrivateKeyNeverAppearsInTheLog(t *testing.T) {
	_, keyPEM := generateKeyPEM(t, true)
	m, err := NewRS256Minter(keyPEM)
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}

	records := captureLogs(t, func() {
		if _, err := m.PlatformToken(); err != nil {
			t.Fatalf("mint: %v", err)
		}
	})

	rendered, _ := json.Marshal(records)
	if bytes.Contains(rendered, []byte("PRIVATE KEY")) {
		t.Fatal("key material appears in the log")
	}
}
