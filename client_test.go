package culperlink

import (
	"bytes"
	"context"
	"encoding/json"
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
	if _, err := c.Decrypt(ctx, sealed, "conversation-2"); !errors.As(err, &api) || api.Code != "DECRYPTION_FAILED" || api.StatusCode != http.StatusUnprocessableEntity {
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
	// No installation serves an audit log to an SDK credential: AuditLog
	// refuses, says where the views are, and sends nothing (G-10).
	entries, err := c.AuditLog(ctx, AuditLogOptions{From: "2026-10-01"})
	if !errors.Is(err, ErrAuditLogNotServed) || entries != nil || !strings.Contains(err.Error(), "/api/v1/audit/v1/") {
		t.Fatalf("AuditLog = %v, %v; want ErrAuditLogNotServed", entries, err)
	}
	if n := cp.hit("/audit/v1/access"); n != 0 {
		t.Fatalf("AuditLog sent %d requests", n)
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
			apiErr(w, http.StatusForbidden, "API_KEY_EXPIRED", "renew at /billing/renew")
			return true
		}
		return false
	})
	c2 := offClient(t, cp)
	if err := c2.Connect(context.Background()); !errors.Is(err, ErrAPIKeyExpired) || errors.Is(err, ErrInvalidSession) ||
		errors.Is(err, ErrLicenceExpired) || !errors.As(err, &api) || api.StatusCode != http.StatusForbidden {
		t.Fatalf("expired key: %v, want ErrAPIKeyExpired carrying 403, and neither ErrInvalidSession nor ErrLicenceExpired", err)
	}

	// The installation's licence, not the key (CULPER-461 G-13): its own
	// sentinel, so the caller looks in the right place.
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/sdk/v1/auth/api-key" {
			apiErr(w, http.StatusForbidden, "LICENCE_EXPIRED", "this installation's licence has expired")
			return true
		}
		return false
	})
	c3 := offClient(t, cp)
	err = c3.Connect(context.Background())
	if !errors.Is(err, ErrLicenceExpired) || errors.Is(err, ErrAPIKeyExpired) || errors.Is(err, ErrInvalidSession) ||
		!errors.As(err, &api) || api.Code != "LICENCE_EXPIRED" || api.StatusCode != http.StatusForbidden {
		t.Fatalf("lapsed licence: %v, want ErrLicenceExpired carrying LICENCE_EXPIRED/403, and neither ErrAPIKeyExpired nor ErrInvalidSession", err)
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

// A request sent again carries the same body every time (CULPER-331). A POST
// is sent again only under the rate limiter's short Retry-After now.
func TestRetriesReplayTheBody(t *testing.T) {
	countPauses(t)
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
		if fails.Add(1) <= 1 {
			w.Header().Set("Retry-After", "1")
			apiErr(w, http.StatusTooManyRequests, "RATE_LIMITED", "slow down")
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
	if len(bodies) != 2 {
		t.Fatalf("attempts = %d, want 2", len(bodies))
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
			apiErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "boom")
			return true
		}
		return false
	})
	c := offClient(t, cp, func(o *Options) { o.MaxRetries = Retries(1) })
	_, err := c.Verify(context.Background(), "p")
	var api *APIError
	if !errors.As(err, &api) || api.Code != "INTERNAL_ERROR" {
		t.Fatalf("Verify: %v, want the service's INTERNAL_ERROR", err)
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
		"passkey ceremony": second(c.FinishPasskeyLogin(ctx, "", &PasskeyAssertion{})),
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

// TestCallsNearTheSessionCapRenewOnce is CULPER-460 G-5. The service clamps a
// renewal to the session's 12-hour cap, so from five minutes before it every
// renewal answers the same expiry, still inside the refresh window. The
// client used to renew on every call there, and the per-address limit shared
// with the API-key route turned that into refusals. It now renews once, uses
// the pair until shortly before the cap, then presents the API key once.
func TestCallsNearTheSessionCapRenewOnce(t *testing.T) {
	cp := newFakeCP(t)
	cp.mu.Lock()
	cp.capAt = time.Now().Add(200 * time.Second).UTC()
	cp.mu.Unlock()
	c := offClient(t, cp)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if _, err := c.Encrypt(ctx, []byte("p"), "ch"); err != nil {
			t.Fatal(err)
		}
	}
	if n := cp.hit("/sdk/v1/auth/renew"); n != 1 {
		t.Fatalf("renewals for 10 calls = %d, want 1", n)
	}
	if n := cp.hit("/sdk/v1/auth/api-key"); n != 1 {
		t.Fatalf("api-key exchanges = %d, want 1", n)
	}

	// Shortly before the cap: one API-key exchange, no further renewal.
	cp.mu.Lock()
	cp.capAt = time.Time{}
	cp.mu.Unlock()
	c.session.mu.Lock()
	c.session.cappedMargin = 10 * time.Minute
	c.session.mu.Unlock()
	for i := 0; i < 5; i++ {
		if _, err := c.Encrypt(ctx, []byte("p"), "ch"); err != nil {
			t.Fatal(err)
		}
	}
	if n := cp.hit("/sdk/v1/auth/api-key"); n != 2 {
		t.Fatalf("api-key exchanges = %d, want 2", n)
	}
	if n := cp.hit("/sdk/v1/auth/renew"); n != 1 {
		t.Fatalf("renewals = %d, want still 1", n)
	}
}

// TestEncryptRefusedSessionIsASessionError is CULPER-460 G-14: a refused data
// token on Encrypt is a session problem, not an encryption failure. It used
// to match ErrEncryptionFailed as well, so a caller (or culperlink-mcp) that
// checks ErrEncryptionFailed first reported a revoked session as an
// encryption failure. Python and TypeScript raise InvalidSessionError here.
func TestEncryptRefusedSessionIsASessionError(t *testing.T) {
	cp := newFakeCP(t)
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/sdk/v1/encrypt" {
			return false
		}
		apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired session")
		return true
	})
	c := offClient(t, cp)
	_, err := c.Encrypt(context.Background(), []byte("p"), "ch")
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("errors.Is(err, ErrInvalidSession) = false, err = %v", err)
	}
	if errors.Is(err, ErrEncryptionFailed) {
		t.Errorf("a refused session matched ErrEncryptionFailed: %v", err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.Code != "UNAUTHORIZED" || api.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the service's code and status were dropped: %v", err)
	}
}

// TestMaxRetriesZeroMeansNoRetries is CULPER-460 G-30: MaxRetries 0 used to
// be indistinguishable from unset and silently meant 3. Retries(0) is now one
// attempt; nil keeps the default of 3; a negative count is refused.
func TestMaxRetriesZeroMeansNoRetries(t *testing.T) {
	countPauses(t)
	tests := []struct {
		name         string
		maxRetries   *int
		wantAttempts int
	}{
		{"zero is no retries", Retries(0), 1},
		{"one is one retry", Retries(1), 2},
		{"nil is the default", nil, defaultMaxRetries + 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := newFakeCP(t)
			cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/sdk/v1/verify" {
					return false
				}
				// A gateway's 502: rule 2 sends a GET again. A 503 with a
				// service code would be definitive and prove nothing here.
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return true
			})
			c := offClient(t, cp, func(o *Options) { o.MaxRetries = tc.maxRetries })
			_, _ = c.Verify(context.Background(), "proof-abc")
			if got := cp.hit("/sdk/v1/verify"); got != tc.wantAttempts {
				t.Fatalf("attempts = %d, want %d", got, tc.wantAttempts)
			}
		})
	}
	if _, err := NewClient(Options{APIKey: "k", Endpoint: "https://x.example", MaxRetries: Retries(-1)}); err == nil {
		t.Fatal("a negative MaxRetries was accepted")
	}
}

// CULPER-462: TagPayload sends the marking in the encrypt body, the payload
// carries the marking and payload version the service returned, and Decrypt
// sends both back; a stripped marking does not decrypt.
func TestTagPayloadSendsTheMarkingAndDecryptReturnsIt(t *testing.T) {
	cp := newFakeCP(t)
	var (
		mu     sync.Mutex
		bodies = map[string]map[string]any{}
	)
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/sdk/v1/encrypt" && r.URL.Path != "/sdk/v1/decrypt" {
			return false
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		bodies[r.URL.Path] = m
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b))
		return false
	})
	c := offClient(t, cp)
	ctx := context.Background()

	plain, err := c.Encrypt(ctx, []byte("p"), "ch")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if _, sent := bodies["/sdk/v1/encrypt"]["cui_marking"]; sent {
		t.Errorf("Encrypt sent a cui_marking; the organisation default must apply")
	}
	mu.Unlock()
	if plain.CUIMarking != "" || plain.PayloadVersion != 2 {
		t.Errorf("Encrypt payload = marking %q version %d, want \"\" and 2", plain.CUIMarking, plain.PayloadVersion)
	}

	ep, err := c.TagPayload(ctx, []byte("secret"), CUIDefenseCSI, "ch")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if got := bodies["/sdk/v1/encrypt"]["cui_marking"]; got != string(CUIDefenseCSI) {
		t.Errorf("TagPayload sent cui_marking %v, want %q", got, CUIDefenseCSI)
	}
	mu.Unlock()
	if ep.CUIMarking != string(CUIDefenseCSI) || ep.PayloadVersion != 2 {
		t.Fatalf("payload = marking %q version %d", ep.CUIMarking, ep.PayloadVersion)
	}
	got, err := c.Decrypt(ctx, ep, "ch")
	if err != nil || string(got) != "secret" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	mu.Lock()
	dec := bodies["/sdk/v1/decrypt"]
	mu.Unlock()
	if dec["cui_marking"] != string(CUIDefenseCSI) || dec["payload_version"] != float64(2) {
		t.Errorf("Decrypt sent cui_marking %v payload_version %v", dec["cui_marking"], dec["payload_version"])
	}

	stripped := *ep
	stripped.CUIMarking = ""
	if _, err := c.Decrypt(ctx, &stripped, "ch"); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("a stripped marking decrypted: %v", err)
	}
}

func TestCUIMarkingPredicates(t *testing.T) {
	sovereign := map[CUIMarking]bool{
		CUIDefenseCSI: true, CUIExportControl: true, CUINuclear: true, CUINavalReactors: true,
		CUIIntelligence: true, CUILawEnforcement: true, CUIExportControlled: true, CUICritical: true,
	}
	all := []CUIMarking{CUIBasic, CUIPrivacy, CUIProprietaryInfo, CUIDefenseCSI, CUIExportControl,
		CUINuclear, CUINavalReactors, CUIIntelligence, CUILawEnforcement, CUIExportControlled,
		CUIFinancial, CUIProcurement, CUIGeodetic, CUICritical, CUITax, CUIStatistical,
		CUIStudentRecords, CUIHealth, CUILegal}
	if len(all) != 19 {
		t.Fatalf("%d markings, want 19", len(all))
	}
	for _, m := range all {
		if !m.IsValid() {
			t.Errorf("%q not valid", m)
		}
		if m.RequiresSovereignNode() != sovereign[m] {
			t.Errorf("%q RequiresSovereignNode = %v", m, !sovereign[m])
		}
	}
	if !CUINone.IsValid() || CUINone.RequiresSovereignNode() || CUIMarking("CUI//BOGUS").IsValid() {
		t.Error("CUINone or an unknown marking misclassified")
	}
}
