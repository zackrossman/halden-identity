package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// TLSConfig names the material used to call an internal service over TLS.
//
// All three are optional. With none set, calls go out over whatever scheme the
// URL names and the default transport applies — which is how this service ran
// before internal TLS existed, and how it still runs until certificates are
// provisioned.
type TLSConfig struct {
	// CABundlePath is the CA that signs the downstream service's certificate.
	// Without it, verification falls back to the system roots, which will not
	// contain an internally-issued certificate.
	CABundlePath string
	// ClientCertPath and ClientKeyPath present this service's own certificate
	// for mutual TLS. Both or neither.
	ClientCertPath string
	ClientKeyPath  string
}

// Configured reports whether any TLS material was supplied.
func (c TLSConfig) Configured() bool {
	return c.CABundlePath != "" || c.ClientCertPath != "" || c.ClientKeyPath != ""
}

// NewClient builds an HTTP client for calling an internal service.
//
// Verification is never disabled. There is no option to skip it, because the
// only reason to reach for one is an internally-issued certificate, and the CA
// bundle is the right answer to that.
func NewClient(timeout time.Duration, cfg TLSConfig) (*http.Client, error) {
	if !cfg.Configured() {
		return &http.Client{Timeout: timeout}, nil
	}

	if (cfg.ClientCertPath == "") != (cfg.ClientKeyPath == "") {
		return nil, errors.New("httpx: client certificate and key must be set together")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CABundlePath != "" {
		pem, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("httpx: read CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			// A bundle that parses to nothing would otherwise leave RootCAs
			// empty, which silently falls back to the system roots.
			return nil, fmt.Errorf("httpx: CA bundle %s contains no certificates", cfg.CABundlePath)
		}
		tlsConfig.RootCAs = pool
	}

	if cfg.ClientCertPath != "" {
		pair, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("httpx: load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}
