package culperlink_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	culperlink "github.com/culper-systems/culperlink-go"
)

// pinnedVectorPEM is a fixed certificate and pinnedVectorSPKI the SPKI hash it
// must produce. Both are frozen bytes, not values recomputed from the code
// under test, so a change to how SPKIPin derives a pin fails here instead of
// silently invalidating every pin a customer has already deployed. Verify
// independently with:
//
//	openssl x509 -in cert.pem -pubkey -noout |
//	  openssl pkey -pubin -outform der |
//	  openssl dgst -sha256 -binary | base64
const pinnedVectorPEM = `-----BEGIN CERTIFICATE-----
MIIBnDCCAUKgAwIBAgIBATAKBggqhkjOPQQDAjAsMSowKAYDVQQDDCFDdWxwZXJM
aW5rIFNESyBQaW5uZWQgVGVzdCBWZWN0b3IwIBcNMjYwODI5MTE0ODEwWhgPMjEy
NjA4MDUxMTQ4MTBaMCwxKjAoBgNVBAMMIUN1bHBlckxpbmsgU0RLIFBpbm5lZCBU
ZXN0IFZlY3RvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNkV5LUhW4HOIkj+
6B/ZECLuiwI0qUMb5rnJR9S6X+pAkrcMeCBfpJsrtsGW03MkBbIH5ewr11Tj0Wub
nOva6dWjUzBRMB0GA1UdDgQWBBRYWmSZCctOQd5OYCs9FoJEe8Wh8TAfBgNVHSME
GDAWgBRYWmSZCctOQd5OYCs9FoJEe8Wh8TAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA0gAMEUCIQDiwJluSSojssLXAiwsitPBEXoAN0cDmNkIXDtdJKmZMQIg
WXOT2CSeVbfbOQJytYTRccV4kMbOJHGPiVOGXdHrVHs=
-----END CERTIFICATE-----
`

const pinnedVectorSPKI = "vvaW88C3ne6KkGjBpZdJt5bdTF9Ioh9LoTxNeQWR5AE="

func TestSPKIPinFromPEMMatchesPinnedVector(t *testing.T) {
	pins, err := culperlink.SPKIPinFromPEM([]byte(pinnedVectorPEM))
	if err != nil {
		t.Fatalf("SPKIPinFromPEM: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("got %d pins, want 1", len(pins))
	}
	if pins[0] != pinnedVectorSPKI {
		t.Errorf("SPKI pin drifted:\n got %q\nwant %q", pins[0], pinnedVectorSPKI)
	}
}

func TestSPKIPinFromPEMRejectsNonCertificate(t *testing.T) {
	for name, input := range map[string]string{
		"empty":     "",
		"not PEM":   "definitely not a certificate",
		"wrong tag": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := culperlink.SPKIPinFromPEM([]byte(input)); !errors.Is(err, culperlink.ErrInvalidCABundle) {
				t.Errorf("got %v, want ErrInvalidCABundle", err)
			}
		})
	}
}

// --- endpoint is required -------------------------------------------------

func TestNewClientRequiresEndpoint(t *testing.T) {
	_, err := culperlink.NewClient(culperlink.Options{APIKey: "test-key"})
	if !errors.Is(err, culperlink.ErrMissingEndpoint) {
		t.Fatalf("got %v, want ErrMissingEndpoint", err)
	}
	// The message must name the setting a caller has to change. An error that
	// only says "endpoint required" sends them to the docs; this one does not.
	if !strings.Contains(err.Error(), "Options.Endpoint") {
		t.Errorf("error does not name the setting: %q", err)
	}
}

func TestNewClientNeverDefaultsToAVendorHost(t *testing.T) {
	// The regression this guards is the one CULPER-350 exists for: a caller
	// who omits Endpoint must not end up pointed at anyone else's service.
	c, err := culperlink.NewClient(culperlink.Options{APIKey: "k", Endpoint: "https://culperlink.internal.example"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	if got := c.Endpoint(); got != "https://culperlink.internal.example" {
		t.Errorf("endpoint rewritten to %q", got)
	}
}

// --- verified against a server using an internal CA -----------------------

type internalCA struct {
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func newInternalCA(t *testing.T) *internalCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Corp Internal Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return &internalCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
		key:     key,
	}
}

// issue returns a server certificate for 127.0.0.1 signed by the internal CA.
func (ca *internalCA) issue(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "culperlink.internal.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:     []string{"culperlink.internal.example", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startInternalCAServer stands up a TLS server presenting a certificate issued
// by an internal CA — the shape a self-hosted defense customer actually runs,
// and one no public trust store will accept.
func startInternalCAServer(t *testing.T, ca *internalCA) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Connect performs the API-key exchange; answer it with a usable
		// token pair so a successful case fails only on TLS, never on
		// protocol.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"session_token": "test-session-token",
			"data_token":    "test-data-token",
			"expires_at":    "2126-01-01T00:00:00Z"
		}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t)},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestTLSAgainstInternalCA(t *testing.T) {
	ca := newInternalCA(t)
	srv := startInternalCAServer(t, ca)

	caPins, err := culperlink.SPKIPinFromPEM(ca.certPEM)
	if err != nil {
		t.Fatalf("pins from CA bundle: %v", err)
	}

	tests := []struct {
		name    string
		tlsOpts culperlink.TLSConfig
		wantErr error // nil means the request must succeed
		wantAny bool  // true means "must fail", without pinning which error
	}{
		{
			name:    "system roots reject an internal CA",
			tlsOpts: culperlink.TLSConfig{},
			wantAny: true,
		},
		{
			name:    "CA bundle supplied inline is trusted",
			tlsOpts: culperlink.TLSConfig{CACertPEM: ca.certPEM},
		},
		{
			name:    "CA bundle plus a matching pin on the CA",
			tlsOpts: culperlink.TLSConfig{CACertPEM: ca.certPEM, PinnedSPKISHA256: caPins},
		},
		{
			name: "a pin that matches nothing in the chain is refused",
			tlsOpts: culperlink.TLSConfig{
				CACertPEM:        ca.certPEM,
				PinnedSPKISHA256: []string{pinnedVectorSPKI},
			},
			wantErr: culperlink.ErrCertificatePinMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := culperlink.NewClient(culperlink.Options{
				APIKey:   "test-key",
				Endpoint: srv.URL,
				Timeout:  5 * time.Second,
				TLS:      tc.tlsOpts,
				// The HTTPS-only client: these pin the Control Plane's
				// trust, which CULPER-413 leaves as it was.
				Tunnel: culperlink.TunnelOptions{Mode: culperlink.TunnelOff},
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			defer func() { _ = c.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err = c.Connect(ctx)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
			case tc.wantAny:
				if err == nil {
					t.Fatal("expected the connection to be refused, but it succeeded")
				}
			default:
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
			}
		})
	}
}

func TestTLSCACertFileIsRead(t *testing.T) {
	ca := newInternalCA(t)
	srv := startInternalCAServer(t, ca)

	path := t.TempDir() + "/internal-ca.pem"
	if err := os.WriteFile(path, ca.certPEM, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	c, err := culperlink.NewClient(culperlink.Options{
		APIKey:   "test-key",
		Endpoint: srv.URL,
		Timeout:  5 * time.Second,
		TLS:      culperlink.TLSConfig{CACertFile: path},
		Tunnel:   culperlink.TunnelOptions{Mode: culperlink.TunnelOff},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("request over internal CA via CACertFile: %v", err)
	}
}

func TestTLSCACertFileMissingIsActionable(t *testing.T) {
	_, err := culperlink.NewClient(culperlink.Options{
		APIKey:   "test-key",
		Endpoint: "https://culperlink.internal.example",
		TLS:      culperlink.TLSConfig{CACertFile: "/nonexistent/ca.pem"},
	})
	if !errors.Is(err, culperlink.ErrInvalidCABundle) {
		t.Fatalf("got %v, want ErrInvalidCABundle", err)
	}
	if !strings.Contains(err.Error(), "/nonexistent/ca.pem") {
		t.Errorf("error does not name the offending path: %q", err)
	}
}

// TestTLSPinMatchesOnlyTheVerifiedChain is CULPER-460 G-2, the auditor's
// attack. The server's leaf chains to a CA the client trusts ("Any Trusted
// CA"), and the server also sends the pinned CA's public certificate, which
// anyone can obtain. Chain verification ignores the extra certificate. The
// old pin check looked at every certificate the server sent, matched the
// appended one, and the API key went to the server. Pins now match the
// verified chain only, so the connection is refused before any request.
func TestTLSPinMatchesOnlyTheVerifiedChain(t *testing.T) {
	trusted := newInternalCA(t)
	pinned := newInternalCA(t)
	pinnedPins, err := culperlink.SPKIPinFromPEM(pinned.certPEM)
	if err != nil {
		t.Fatalf("pins: %v", err)
	}
	leaf := trusted.issue(t)
	leafPins, err := culperlink.SPKIPinFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}))
	if err != nil {
		t.Fatalf("leaf pins: %v", err)
	}

	var mu sync.Mutex
	var received []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_token":"s","data_token":"d","expires_at":"2126-01-01T00:00:00Z"}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.Certificate[0], pinned.cert.Raw},
			PrivateKey:  leaf.PrivateKey,
		}},
		MinVersion: tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tests := []struct {
		name    string
		pins    []string
		wantErr error
	}{
		{name: "the appended pinned CA does not satisfy the pin", pins: pinnedPins, wantErr: culperlink.ErrCertificatePinMismatch},
		{name: "the verified leaf still satisfies a leaf pin", pins: leafPins},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			received = nil
			mu.Unlock()
			c, err := culperlink.NewClient(culperlink.Options{
				APIKey:   "clk_live_PIN_SECRET",
				Endpoint: srv.URL,
				Timeout:  5 * time.Second,
				TLS:      culperlink.TLSConfig{CACertPEM: trusted.certPEM, PinnedSPKISHA256: tc.pins},
				Tunnel:   culperlink.TunnelOptions{Mode: culperlink.TunnelOff},
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			defer func() { _ = c.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = c.Connect(ctx)
			mu.Lock()
			got := append([]string(nil), received...)
			mu.Unlock()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			if len(got) != 0 {
				t.Fatalf("server received %d request(s) though the pin failed: %q", len(got), got)
			}
		})
	}
}
