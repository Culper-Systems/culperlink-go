package culperlink

// tls.go — TLS trust configuration for the Control Plane connection.
//
// WHY THIS EXISTS. CulperLink is a customer-operated product: the service the
// SDK talks to is the customer's own installation, presenting the customer's
// own certificate. Defence and regulated customers routinely issue those
// certificates from an internal CA that is not in any public trust store, so
// "use the system roots" is not a usable default for them.
//
// Before CULPER-350 the only way to handle that was Options.HTTPClient — a
// caller had to construct an *http.Client, a *tls.Config and an x509.CertPool
// themselves, and nothing documented that they should. The predictable outcome
// of an undocumented escape hatch guarding a hard problem is that people
// disable verification instead, which is the exact opposite of what Figure 6's
// boundary 1 asks for. TLSConfig makes the supported path the easy one.
//
// WHAT IS DELIBERATELY ABSENT. There is no InsecureSkipVerify field. A product
// whose security claim is transport integrity should not ship a one-line way
// to switch it off. Options.HTTPClient still lets a caller build whatever
// *tls.Config they like, so nothing is actually prevented — but it is no
// longer the shortest path, and it does not look sanctioned.
//
// PINNING SHAPE. Pins are SHA-256 over the certificate's SubjectPublicKeyInfo,
// matched against *any* certificate in the chain the server presents, not just
// the leaf. Pinning the internal CA rather than the leaf is what lets a
// customer rotate server certificates on their own schedule without every
// deployed client failing at renewal — a leaf pin with no rotation path is an
// outage waiting for a date.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// TLSConfig describes how the SDK verifies the CulperLink service's
// certificate. The zero value verifies against the host's system trust store
// with a TLS 1.3 floor, which is correct for an installation fronted by a
// publicly-trusted certificate.
//
// It is ignored entirely when Options.HTTPClient is supplied — a caller who
// brings their own client owns its transport, and silently rewriting it would
// be worse than doing nothing.
type TLSConfig struct {
	// CACertPEM is a PEM bundle of certificates to trust, supplied inline.
	// Typically the customer's internal root or issuing CA.
	CACertPEM []byte

	// CACertFile is a path to a PEM bundle to trust. Read once, at client
	// construction. If both CACertPEM and CACertFile are set, both are added.
	CACertFile string

	// AppendSystemRoots controls whether the host's system trust store is
	// retained alongside a supplied CA bundle. False (the default) means a
	// supplied bundle *replaces* the system roots, so an installation behind
	// an internal CA will not silently accept a publicly-issued certificate
	// for the same hostname. Set true only when the deployment genuinely
	// serves both.
	AppendSystemRoots bool

	// PinnedSPKISHA256 is a set of base64-encoded SHA-256 hashes over
	// SubjectPublicKeyInfo. When non-empty, a connection is rejected unless
	// some certificate in the presented chain matches one of them, in
	// addition to the chain verifying normally. Pin the CA, not the leaf, if
	// you intend to rotate server certificates. Compute values with
	// SPKIPinFromPEM.
	PinnedSPKISHA256 []string

	// MinVersion is the minimum acceptable TLS version. Defaults to TLS 1.3
	// per Figure 6, boundary 1. Lower it only for an installation behind a
	// terminator that cannot yet do 1.3.
	MinVersion uint16

	// ServerName overrides the SNI name and the name the certificate is
	// verified against. Needed only when reaching an installation by an
	// address its certificate does not name, such as through a tunnel.
	ServerName string
}

// SPKIPin returns the base64-encoded SHA-256 hash of a certificate's
// SubjectPublicKeyInfo — the value TLSConfig.PinnedSPKISHA256 expects.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// SPKIPinFromPEM returns the SPKI pins for every certificate in a PEM bundle,
// in the order they appear. Use it to derive the value to hand
// TLSConfig.PinnedSPKISHA256 from the CA certificate you already have:
//
//	pins, err := culperlink.SPKIPinFromPEM(caPEM)
//
// Equivalent to, and checkable against:
//
//	openssl x509 -in ca.pem -pubkey -noout |
//	  openssl pkey -pubin -outform der |
//	  openssl dgst -sha256 -binary | base64
func SPKIPinFromPEM(pemBytes []byte) ([]string, error) {
	var pins []string
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCABundle, err)
		}
		pins = append(pins, SPKIPin(cert))
	}
	if len(pins) == 0 {
		return nil, ErrInvalidCABundle
	}
	return pins, nil
}

// isZero reports whether the config asks for anything beyond default system
// trust, so NewClient can skip building a custom transport when it does not.
func (t TLSConfig) isZero() bool {
	return len(t.CACertPEM) == 0 &&
		t.CACertFile == "" &&
		!t.AppendSystemRoots &&
		len(t.PinnedSPKISHA256) == 0 &&
		t.MinVersion == 0 &&
		t.ServerName == ""
}

// rootPool assembles the trust store this config describes. It returns nil
// when no CA material was supplied, which tells crypto/tls to use the system
// roots.
func (t TLSConfig) rootPool() (*x509.CertPool, error) {
	if len(t.CACertPEM) == 0 && t.CACertFile == "" {
		return nil, nil
	}

	var pool *x509.CertPool
	if t.AppendSystemRoots {
		sys, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("culperlink: reading system trust store: %w", err)
		}
		pool = sys
	} else {
		pool = x509.NewCertPool()
	}

	if len(t.CACertPEM) > 0 {
		if !pool.AppendCertsFromPEM(t.CACertPEM) {
			return nil, fmt.Errorf("%w: TLS.CACertPEM contained no certificate", ErrInvalidCABundle)
		}
	}
	if t.CACertFile != "" {
		b, err := os.ReadFile(t.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("%w: reading TLS.CACertFile %q: %v", ErrInvalidCABundle, t.CACertFile, err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("%w: TLS.CACertFile %q contained no certificate", ErrInvalidCABundle, t.CACertFile)
		}
	}
	return pool, nil
}

// verifyPins is installed as tls.Config.VerifyPeerCertificate. It runs in
// addition to normal chain verification, never instead of it: a pin that
// matched would not rescue a chain that failed to verify, because this
// callback is not reached when verification fails.
//
// It considers both the certificates the server actually sent and the chains
// crypto/tls built to verify them. That distinction is not academic. A server
// configured with only its leaf certificate — a common and not incorrect
// setup when the client already holds the issuing CA — sends exactly one
// certificate, so a customer who pinned their internal *root* would find the
// pin never matching if only the presented bytes were checked. The verified
// chain carries the root that the supplied CA bundle anchored, so pinning the
// CA works in both server configurations, which is what makes "pin the CA so
// you can rotate leaves" honest advice rather than a trap.
func (t TLSConfig) verifyPins(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(t.PinnedSPKISHA256) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(t.PinnedSPKISHA256))
	for _, p := range t.PinnedSPKISHA256 {
		if p = strings.TrimSpace(p); p != "" {
			want[p] = struct{}{}
		}
	}

	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		if _, ok := want[SPKIPin(cert)]; ok {
			return nil
		}
	}
	for _, chain := range verifiedChains {
		for _, cert := range chain {
			if _, ok := want[SPKIPin(cert)]; ok {
				return nil
			}
		}
	}
	return ErrCertificatePinMismatch
}

// tlsConfig renders the *tls.Config this TLSConfig describes.
func (t TLSConfig) tlsConfig() (*tls.Config, error) {
	pool, err := t.rootPool()
	if err != nil {
		return nil, err
	}

	minVersion := t.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS13
	}

	cfg := &tls.Config{
		MinVersion: minVersion,
		RootCAs:    pool,
		ServerName: t.ServerName,
	}
	if len(t.PinnedSPKISHA256) > 0 {
		cfg.VerifyPeerCertificate = t.verifyPins
	}
	return cfg, nil
}

// httpClient builds an *http.Client whose transport carries this config. The
// transport is cloned from http.DefaultTransport so connection pooling,
// proxy handling and HTTP/2 behave as they do everywhere else in the process.
func (t TLSConfig) httpClient(timeout time.Duration) (*http.Client, error) {
	cfg, err := t.tlsConfig()
	if err != nil {
		return nil, err
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("culperlink: http.DefaultTransport is not *http.Transport; supply Options.HTTPClient instead")
	}
	tr := base.Clone()
	tr.TLSClientConfig = cfg
	// Clone() carries ForceAttemptHTTP2, but a non-nil TLSClientConfig
	// disables the automatic h2 upgrade unless NextProtos says otherwise.
	tr.ForceAttemptHTTP2 = true

	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// caPEM is the CA bundle this config names, inline and from file, as PEM: the
// trust anchors the daemon is given for the node's handshake listener when
// TunnelOptions.RootCAsPEM is unset. Nil when the config names none, which
// leaves the daemon on its system pool; the candidate's SPKI pin is checked
// either way.
func (t TLSConfig) caPEM() ([]byte, error) {
	var out []byte
	if len(t.CACertPEM) > 0 {
		out = append(out, t.CACertPEM...)
		out = append(out, '\n')
	}
	if t.CACertFile != "" {
		b, err := os.ReadFile(t.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("%w: reading TLS.CACertFile %q: %v", ErrInvalidCABundle, t.CACertFile, err)
		}
		out = append(out, b...)
	}
	return out, nil
}
