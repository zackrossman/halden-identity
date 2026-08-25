package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestNewClient_NoMaterialUsesTheDefaultTransport(t *testing.T) {
	// This service ran without internal TLS before, and must keep running that
	// way until certificates are provisioned.
	c, err := NewClient(5*time.Second, TLSConfig{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Transport != nil {
		t.Errorf("Transport = %T, want nil (the default)", c.Transport)
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", c.Timeout)
	}
}

func TestNewClient_CABundleBecomesTheRootPool(t *testing.T) {
	dir := t.TempDir()
	ca := issueCAPEM(t)
	c, err := NewClient(time.Second, TLSConfig{CABundlePath: writeFile(t, dir, "ca.pem", ca)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("RootCAs is nil; verification would fall back to the system roots")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", tr.TLSClientConfig.MinVersion)
	}
}

func TestNewClient_RejectsABundleThatParsesToNothing(t *testing.T) {
	// The dangerous case: an unusable bundle would leave RootCAs empty, which
	// silently falls back to the system roots and looks like it worked.
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not pem":      "this is not a certificate",
		"empty":        "",
		"pem, no cert": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeFile(t, dir, "bundle-"+name+".pem", content)
			if _, err := NewClient(time.Second, TLSConfig{CABundlePath: path}); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestNewClient_MissingBundleFileIsAnError(t *testing.T) {
	if _, err := NewClient(time.Second, TLSConfig{CABundlePath: "/no/such/ca.pem"}); err == nil {
		t.Fatal("expected an error, got none")
	}
}

func TestNewClient_ClientCertAndKeyMustBeSetTogether(t *testing.T) {
	for name, cfg := range map[string]TLSConfig{
		"cert without key": {ClientCertPath: "/tls/c.pem"},
		"key without cert": {ClientKeyPath: "/tls/k.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(time.Second, cfg); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestNewClient_NeverDisablesVerification(t *testing.T) {
	// There is no code path that sets InsecureSkipVerify. The reason to reach
	// for one is an internally-issued certificate, and the CA bundle is the
	// answer to that.
	dir := t.TempDir()
	c, err := NewClient(time.Second, TLSConfig{CABundlePath: writeFile(t, dir, "ca.pem", issueCAPEM(t))})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tr := c.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is set")
	}
}

func TestTLSConfig_Configured(t *testing.T) {
	if (TLSConfig{}).Configured() {
		t.Error("empty config reported as configured")
	}
	for name, cfg := range map[string]TLSConfig{
		"ca":   {CABundlePath: "a"},
		"cert": {ClientCertPath: "a"},
		"key":  {ClientKeyPath: "a"},
	} {
		if !cfg.Configured() {
			t.Errorf("%s: reported as not configured", name)
		}
	}
}

// issueCAPEM returns a self-signed certificate usable as a CA bundle entry.
func issueCAPEM(t *testing.T) string {
	t.Helper()
	pem, _ := selfSignedPEM(t)
	return pem
}

func TestCertPoolActuallyAcceptsTheBundle(t *testing.T) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(issueCAPEM(t))) {
		t.Fatal("test helper produced a bundle x509 will not parse")
	}
}
