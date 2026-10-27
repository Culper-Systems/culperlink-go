package culperlink

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// offClient is the HTTPS-only client against the stub Control Plane, trusting
// its certificate through Options.TLS as a customer with a private CA would.
func offClient(t *testing.T, cp *fakeCP, mut ...func(*Options)) *Client {
	t.Helper()
	opts := Options{
		APIKey:   testAPIKey,
		Endpoint: cp.srv.URL,
		TLS:      TLSConfig{CACertFile: cp.caPEMFile(t)},
		Tunnel:   TunnelOptions{Mode: TunnelOff},
	}
	for _, m := range mut {
		m(&opts)
	}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestNewClientValidates(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want error
	}{
		{"no api key", Options{Endpoint: "https://x"}, ErrMissingAPIKey},
		{"no endpoint", Options{APIKey: "k"}, ErrMissingEndpoint},
		{"bad tunnel mode", Options{APIKey: "k", Endpoint: "https://x", Tunnel: TunnelOptions{Mode: "wireguard"}}, ErrInvalidTunnelMode},
		{"unreadable CA file", Options{APIKey: "k", Endpoint: "https://x", TLS: TLSConfig{CACertFile: "/nonexistent/ca.pem"}}, ErrInvalidCABundle},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewClient(tt.opts); !errors.Is(err, tt.want) {
				t.Fatalf("NewClient: %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewClientDoesNoIOAndDefaultsToTheTunnel(t *testing.T) {
	c, err := NewClient(Options{APIKey: "k", Endpoint: "https://unreachable.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if c.opts.Tunnel.Mode != TunnelNetstack || c.tunnel == nil {
		t.Fatalf("default mode = %q, tunnel = %v; want netstack with a tunnel", c.opts.Tunnel.Mode, c.tunnel)
	}
	if c.opts.UserAgent != "culperlink-go/"+Version {
		t.Fatalf("user agent %q", c.opts.UserAgent)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// The four quickstart calls in TunnelOff, each with its plane's credential
// and no other: the stub records any request that carried the wrong one.
func TestQuickstartCallsCarryTheirPlanesCredential(t *testing.T) {
	cp := newFakeCP(t)
	c := offClient(t, cp)
	ctx := context.Background()

	sealed, err := c.Encrypt(ctx, []byte("the payload"), "conversation-1")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := c.Decrypt(ctx, sealed, "conversation-1")
	if err != nil || string(opened) != "the payload" {
		t.Fatalf("Decrypt = %q, %v", opened, err)
	}
	if _, err := c.Decrypt(ctx, sealed, "conversation-2"); !errors.Is(err, ErrDecryptionFailed) || !errors.Is(err, ErrEncryptionFailed) {
		t.Fatalf("wrong channel: %v, want ErrDecryptionFailed (and ErrEncryptionFailed)", err)
	}
	var api *APIError
	if _, err := c.Decrypt(ctx, sealed, "conversation-2"); !errors.As(err, &api) || api.Code != "DECRYPTION_FAILED" || api.StatusCode != 400 {
		t.Fatalf("wrong channel should keep the service's code and status: %v", err)
	}
	proof, err := c.Attest(ctx, "doc", []byte("fingerprint"))
	if err != nil || proof.ProofHash != "proof-abc" {
		t.Fatalf("Attest = %+v, %v", proof, err)
	}
	ok, err := c.Verify(ctx, proof.ProofHash)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	entries, err := c.AuditLog(ctx, AuditLogOptions{From: "2026-10-01"})
	if err != nil || len(entries) != 1 {
		t.Fatalf("AuditLog = %v, %v", entries, err)
	}
	if v := cp.v.get(); len(v) > 0 {
		t.Fatalf("plane violations: %v", v)
	}
	if n := cp.hit("/sdk/v1/auth/api-key"); n != 1 {
		t.Fatalf("api-key exchanges = %d, want 1", n)
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 0 {
		t.Fatalf("TunnelOff requested gateway selection %d times", n)
	}
	s := c.CurrentSession()
	if s == nil || s.Tier != TierEnterprise || s.Tunnel == nil || s.Tunnel.State != "off" {
		t.Fatalf("CurrentSession = %+v", s)
	}
}

func TestTokenExchangeErrors(t *testing.T) {
	cp := newFakeCP(t)
	c := offClient(t, cp, func(o *Options) { o.APIKey = "wrong" })
	_, err := c.Encrypt(context.Background(), []byte("x"), "ch")
	var api *APIError
	if !errors.Is(err, ErrInvalidSession) || !errors.As(err, &api) || api.Code != "UNAUTHORIZED" || api.StatusCode != 401 {
		t.Fatalf("bad key: %v, want ErrInvalidSession carrying UNAUTHORIZED/401", err)
	}

	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/sdk/v1/auth/api-key" {
			apiErr(w, http.StatusUnauthorized, "API_KEY_EXPIRED", "renew at /billing/renew")
			return true
		}
		return false
	})
	c2 := offClient(t, cp)
	if err := c2.Connect(context.Background()); !errors.Is(err, ErrAPIKeyExpired) || errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expired key: %v, want ErrAPIKeyExpired and not ErrInvalidSession", err)
	}
}

func TestHalfAPairIsRefused(t *testing.T) {
	cp := newFakeCP(t)
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/sdk/v1/auth/api-key" {
			writeJSON(w, http.StatusOK, map[string]any{"session_token": "st", "expires_at": time.Now().Add(time.Hour)})
			return true
		}
		return false
	})
	c := offClient(t, cp)
	if err := c.Connect(context.Background()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("half a pair: %v, want ErrInvalidSession", err)
	}
}

// Near expiry the client renews on session_token, never the API key, and
// never the data token.
func TestRenewalPresentsTheSessionTokenOnly(t *testing.T) {
	cp := newFakeCP(t)
	cp.ttl = time.Minute // inside the five-minute refresh window
	c := offClient(t, cp)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Attest(ctx, "doc", nil); err != nil {
		t.Fatal(err)
	}
	if n := cp.hit("/sdk/v1/auth/renew"); n == 0 {
		t.Fatal("no renewal inside the refresh window")
	}
	if n := cp.hit("/sdk/v1/auth/api-key"); n != 1 {
		t.Fatalf("api-key exchanges = %d, want 1", n)
	}
	if v := cp.v.get(); len(v) > 0 {
		t.Fatalf("violations: %v", v)
	}
}

// A retried request carries the same body every time (CULPER-331).
func TestRetriesReplayTheBody(t *testing.T) {
	cp := newFakeCP(t)
	var fails atomic.Int32
	var (
		mu     sync.Mutex
		bodies [][]byte
	)
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/sdk/v1/encrypt" {
			return false
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		if fails.Add(1) <= 2 {
			apiErr(w, http.StatusServiceUnavailable, "UNAVAILABLE", "try again")
			return true
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		return false
	})
	c := offClient(t, cp)
	if _, err := c.Encrypt(context.Background(), []byte("replayed"), "ch"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("attempts = %d, want 3", len(bodies))
	}
	for i, b := range bodies {
		if !bytes.Equal(b, bodies[0]) || len(b) == 0 {
			t.Fatalf("attempt %d body %q differs from %q", i, b, bodies[0])
		}
	}
}

func TestFourHundredsAreNotRetried(t *testing.T) {
	cp := newFakeCP(t)
	var n atomic.Int32
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/sdk/v1/attest" {
			n.Add(1)
			apiErr(w, http.StatusTooManyRequests, "RATE_LIMITED", "slow down")
			return true
		}
		return false
	})
	c := offClient(t, cp)
	if _, err := c.Attest(context.Background(), "doc", nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Attest: %v, want ErrRateLimited", err)
	}
	if n.Load() != 1 {
		t.Fatalf("attempts = %d, want 1", n.Load())
	}
}

func TestPersistentFiveHundredIsTheServicesError(t *testing.T) {
	cp := newFakeCP(t)
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/sdk/v1/verify" {
			apiErr(w, http.StatusInternalServerError, "INTERNAL", "boom")
			return true
		}
		return false
	})
	c := offClient(t, cp, func(o *Options) { o.MaxRetries = 1 })
	_, err := c.Verify(context.Background(), "p")
	var api *APIError
	if !errors.As(err, &api) || api.Code != "INTERNAL" {
		t.Fatalf("Verify: %v, want the service's INTERNAL", err)
	}
}

func TestClosedClientRefuses(t *testing.T) {
	cp := newFakeCP(t)
	c := offClient(t, cp)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.Encrypt(context.Background(), []byte("x"), "ch"); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Encrypt after Close: %v", err)
	}
	if !c.IsClosed() {
		t.Fatal("IsClosed = false")
	}
}

func TestArgumentChecks(t *testing.T) {
	c, err := NewClient(Options{APIKey: "k", Endpoint: "https://unreachable.invalid", Tunnel: TunnelOptions{Mode: TunnelOff}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, err := range map[string]error{
		"encrypt payload":  second(c.Encrypt(ctx, nil, "ch")),
		"encrypt channel":  second(c.Encrypt(ctx, []byte("x"), "")),
		"decrypt payload":  second(c.Decrypt(ctx, nil, "ch")),
		"decrypt channel":  second(c.Decrypt(ctx, &EncryptedPayload{}, "")),
		"attest subject":   second(c.Attest(ctx, "", nil)),
		"verify hash":      second(c.Verify(ctx, "")),
		"tag marking":      second(c.TagPayload(ctx, []byte("x"), "CUI//BOGUS", "ch")),
		"passkey username": second(c.BeginPasskeyAuth(ctx, "")),
	} {
		if err == nil || !strings.HasPrefix(err.Error(), "culperlink: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func second[T any](_ T, err error) error { return err }

// The tier values are the service's stored vocabulary, written as literals
// here so a change to the constants is a visible change to this test.
func TestTierValues(t *testing.T) {
	if TierSovereign != "sovereign" || TierEnterprise != "enterprise" || TierAIInfrastructure != "ai_infrastructure" {
		t.Fatal("tier values drifted from the service's vocabulary")
	}
}
