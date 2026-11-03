package culperlink

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func skipWithoutUnixSockets(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("the daemon's control transport is a Unix socket; not on %s", runtime.GOOS)
	}
}

// tunnelClient is a netstack client against the stub Control Plane, driving
// the in-process fake daemon through DaemonSocket.
func tunnelClient(t *testing.T, cp *fakeCP, d *fakeDaemon, mut ...func(*Options)) *Client {
	t.Helper()
	opts := Options{
		APIKey:   testAPIKey,
		Endpoint: cp.srv.URL,
		TLS:      TLSConfig{CACertFile: cp.caPEMFile(t)},
		Tunnel:   TunnelOptions{DaemonSocket: d.socket},
		Timeout:  10 * time.Second,
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

// The quickstart through the tunnel: the payload calls go to the node's
// tunnel address through the daemon's proxy, carrying data_token alone; the
// Control Plane sees selection and attest/verify, and no payload route.
func TestEncryptAndDecryptRideTheTunnel(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	ctx := context.Background()

	sealed, err := c.Encrypt(ctx, []byte("through the tunnel"), "conversation-1")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := c.Decrypt(ctx, sealed, "conversation-1")
	if err != nil || string(opened) != "through the tunnel" {
		t.Fatalf("Decrypt = %q, %v", opened, err)
	}
	if _, err := c.Decrypt(ctx, sealed, "conversation-2"); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("wrong channel through the tunnel: %v", err)
	}
	proof, err := c.Attest(ctx, "doc", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Verify(ctx, proof.ProofHash); err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}

	if n := cp.hit("/sdk/v1/encrypt") + cp.hit("/sdk/v1/decrypt"); n != 0 {
		t.Fatalf("the Control Plane saw %d payload requests", n)
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 1 {
		t.Fatalf("selections = %d, want 1", n)
	}
	if v := append(cp.v.get(), d.v.get()...); len(v) > 0 {
		t.Fatalf("plane violations: %v", v)
	}
	ops := d.opList()
	if len(ops) < 2 || ops[0] != "status" || ops[1] != "connect" {
		t.Fatalf("daemon ops = %v, want status (the version check) before connect", ops)
	}
	d.mu.Lock()
	req := d.connectReqs[0]
	d.mu.Unlock()
	if req["data_token"] != "dt-1" || req["mode"] != "netstack" {
		t.Fatalf("connect carried data_token=%v mode=%v", req["data_token"], req["mode"])
	}
	if _, ok := req["session_token"]; ok {
		t.Fatal("connect carried a session token")
	}
	if pem, _ := req["root_cas_pem"].(string); !strings.Contains(pem, "BEGIN CERTIFICATE") {
		t.Fatal("connect did not carry Options.TLS's CA bundle as the node's trust anchor")
	}
	cands, _ := req["candidates"].([]any)
	if len(cands) != 1 || cands[0].(map[string]any)["spki_pin"] == "" {
		t.Fatalf("connect candidates = %v", cands)
	}

	st := c.CurrentSession().Tunnel
	if st.State != "up" || st.Gateway == nil || st.Gateway.ID != fakeNodeID || st.NodeTunnelIP != nodeTunnelIP || st.LastHandshake.IsZero() {
		t.Fatalf("tunnel status = %+v", st)
	}
	if st.DaemonPID != 0 {
		t.Fatalf("DaemonPID = %d for a daemon this client did not start", st.DaemonPID)
	}

	// Close disconnects, and leaves a daemon it did not start running.
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if ops := d.opList(); ops[len(ops)-1] != "disconnect" {
		t.Fatalf("last op = %q, want disconnect", ops[len(ops)-1])
	}
}

// The version range is checked before any token is handed over, and before
// anything is selected.
func TestDaemonOutsideTheRangeIsRefusedBeforeTheToken(t *testing.T) {
	skipWithoutUnixSockets(t)
	for _, v := range []any{"0.1.9", "0.3.0", "1.0.0", nil, "", "dev", 2} {
		cp := newFakeCP(t)
		d := newFakeDaemon(t, v)
		c := tunnelClient(t, cp, d)
		err := c.Connect(context.Background())
		if !errors.Is(err, ErrTunnelDaemonIncompatible) || !errors.Is(err, ErrTunnelUnavailable) {
			t.Fatalf("version %v: %v, want ErrTunnelDaemonIncompatible", v, err)
		}
		if !strings.Contains(err.Error(), "culperlink-go "+Version) {
			t.Fatalf("version %v: message does not name this library's version: %v", v, err)
		}
		if ops := d.opList(); !slices.Equal(ops, []string{"status"}) {
			t.Fatalf("version %v: daemon ops = %v, want only the status probe", v, ops)
		}
		if n := cp.hit("/sdk/v1/gateways/select"); n != 0 {
			t.Fatalf("version %v: selected %d times", v, n)
		}
	}
}

func TestDaemonVersionParsing(t *testing.T) {
	tests := []struct {
		in any
		ok bool
	}{
		{"0.2.0", true}, {"v0.2.5", true}, {"0.2.0-rc.1", true}, {"0.2.0+build", true},
		{"0.2", false}, {"0.2.x", false}, {"", false}, {nil, false}, {1.5, false}, {"0.-1.0", false},
	}
	for _, tt := range tests {
		if _, ok := parseVersion(tt.in); ok != tt.ok {
			t.Errorf("parseVersion(%v) ok = %v, want %v", tt.in, ok, tt.ok)
		}
	}
	if checkDaemonVersion("0.2.0") != nil || checkDaemonVersion("0.2.99") != nil {
		t.Fatal("a daemon inside the range was refused")
	}
}

// The pinned range: written as literals so moving it is a visible change, and
// equal to the Python and TypeScript libraries' of the same release.
func TestDaemonVersionRangeIsPinned(t *testing.T) {
	if DaemonVersionMin != "0.2.0" || DaemonVersionMax != "0.3.0" {
		t.Fatalf("range [%s, %s) moved; move it deliberately, with the other two libraries", DaemonVersionMin, DaemonVersionMax)
	}
}

func TestNonLoopbackProxyAddressIsRefused(t *testing.T) {
	skipWithoutUnixSockets(t)
	for _, addr := range []string{"192.0.2.10:8118", "0.0.0.0:8118", "[2001:db8::1]:8118", "localhost:8118", "127.0.0.1"} {
		cp := newFakeCP(t)
		d := newFakeDaemon(t, "0.2.0")
		d.set(func(d *fakeDaemon) { d.httpAddr = addr })
		c := tunnelClient(t, cp, d)
		_, err := c.Encrypt(context.Background(), []byte("x"), "ch")
		if !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("%s: %v, want a loopback refusal", addr, err)
		}
		if ops := d.opList(); ops[len(ops)-1] != "disconnect" {
			t.Fatalf("%s: last op %q, want disconnect", addr, ops[len(ops)-1])
		}
	}
	if !isLoopbackHostPort("127.0.0.1:1") || !isLoopbackHostPort("[::1]:1") || !isLoopbackHostPort("127.8.9.10:65535") {
		t.Fatal("a loopback address was refused")
	}
}

func TestConnectRefusalIsTunnelUnavailable(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	d.set(func(d *fakeDaemon) { d.connectErr = "handshake: every candidate refused" })
	c := tunnelClient(t, cp, d)
	err := c.Connect(context.Background())
	if !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "every candidate refused") {
		t.Fatalf("Connect: %v", err)
	}
}

func TestSelectionRefusals(t *testing.T) {
	skipWithoutUnixSockets(t)
	tests := []struct {
		name   string
		answer func(w http.ResponseWriter)
		want   error
	}{
		{"gateway unavailable", func(w http.ResponseWriter) {
			apiErr(w, http.StatusServiceUnavailable, "GATEWAY_UNAVAILABLE", "pool has no eligible node")
		}, ErrSovereignNodeUnavailable},
		{"not served", func(w http.ResponseWriter) {
			apiErr(w, http.StatusNotFound, "NOT_FOUND", "no such route")
		}, ErrTunnelUnavailable},
		{"all offline", func(w http.ResponseWriter) {
			c := candidate(fakeNodeID, "US", "us-east-1")
			c["status"] = "offline"
			writeJSON(w, http.StatusOK, map[string]any{"candidates": []any{c}})
		}, ErrSovereignNodeUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := newFakeCP(t)
			cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/sdk/v1/gateways/select" {
					tt.answer(w)
					return true
				}
				return false
			})
			d := newFakeDaemon(t, "0.2.0")
			c := tunnelClient(t, cp, d, func(o *Options) { o.MaxRetries = Retries(1) })
			if err := c.Connect(context.Background()); !errors.Is(err, tt.want) {
				t.Fatalf("Connect: %v, want %v", err, tt.want)
			}
			if slices.Contains(d.opList(), "connect") {
				t.Fatal("the daemon was asked to connect after selection failed")
			}
		})
	}
}

// The geofence is re-applied to the list the Control Plane returned: a node
// outside it is never handed to the daemon, and selection carries the
// marking, the pool and the position.
func TestGeofenceIsReappliedAndSelectionCarriesTheMarking(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	cp.candidates = []map[string]any{
		candidate("node-cn", "CN", "cn-north-1"),
		candidate("node-de", "DE", "eu-central-1"),
		candidate(fakeNodeID, "US", "us-east-1"),
	}
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d, func(o *Options) {
		o.Tunnel.CUIMarking = CUIExportControl
		o.Tunnel.Country = "US"
		o.Tunnel.MaxCandidates = 3
	})
	c.SetSovereignPool("pool-7")
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	cands := d.connectReqs[0]["candidates"].([]any)
	d.mu.Unlock()
	if len(cands) != 1 || cands[0].(map[string]any)["id"] != fakeNodeID {
		t.Fatalf("handed to the daemon: %v, want only %s", cands, fakeNodeID)
	}
	cp.mu.Lock()
	body := cp.selectBody[0]
	cp.mu.Unlock()
	if body["cui_marking"] != string(CUIExportControl) || body["pool_id"] != "pool-7" || body["country"] != "US" || body["max_candidates"] != float64(3) {
		t.Fatalf("selection body = %v", body)
	}

	// The three lists, pinned.
	g := geofenceFor(CUIDefenseCSI)
	if !slices.Equal(g.allowedCountries, []string{"US"}) ||
		!slices.Equal(g.allowedRegions, []string{"us-gov-west-1", "us-gov-east-1"}) ||
		!slices.Equal(g.disallowedCountries, []string{"CN", "RU", "IR", "KP", "SY", "CU", "VE", "BY", "MM"}) {
		t.Fatalf("geofence lists drifted: %+v", g)
	}
	if g := geofenceFor(CUINone); g.violation(GatewayDescriptor{Country: "CN"}) != "" {
		t.Fatal("no marking should mean no fence")
	}
	if g := geofenceFor(CUINuclear); g.violation(GatewayDescriptor{Country: "US", Region: "us-east-1"}) == "" {
		t.Fatal("nuclear outside GovCloud was admitted")
	}
}

func TestPolicyIsHandedToTheDaemon(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	cp.policy = map[string]any{"mode": "prefixes", "prefixes": []string{"10.50.0.0/16"}, "dns": map[string]any{"mode": "tunnel", "resolvers": []string{"10.50.0.53"}}}
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	p, _ := d.connectReqs[0]["policy"].(map[string]any)
	d.mu.Unlock()
	if p["mode"] != "prefixes" || p["dns_through_tunnel"] != true || len(p["resolvers"].([]any)) != 1 {
		t.Fatalf("policy = %v", p)
	}
	// A bare string DNS mode reads the same as the object.
	var dp TunnelDNSPolicy
	if err := dp.UnmarshalJSON([]byte(`"tunnel"`)); err != nil || dp.Mode != "tunnel" {
		t.Fatalf("bare-string dns: %+v, %v", dp, err)
	}
	if policyForDaemon(nil) != nil {
		t.Fatal("an absent policy should be the daemon's default")
	}
}

// A request the tunnel could not carry asks the daemon; a tunnel it reports
// down is dropped and re-selected and re-established. Since CULPER-467 the
// proxy's 502 says the encrypt never reached the node ("not-sent"), so the
// same call is sent again on the new tunnel (retry.go, rule 1). Before, the
// proxy could not say, and the call failed.
func TestTunnelDownIsReestablished(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	ctx := context.Background()
	if _, err := c.Encrypt(ctx, []byte("one"), "ch"); err != nil {
		t.Fatal(err)
	}
	// The tunnel drops: the proxy answers 502 not-sent and the daemon
	// reports down.
	d.set(func(d *fakeDaemon) { d.down, d.connected = true, false })
	if _, err := c.Encrypt(ctx, []byte("two"), "ch"); err != nil {
		t.Fatalf("Encrypt into the dropped tunnel was not carried on the new one: %v", err)
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 2 {
		t.Fatalf("selections = %d, want 2 (one re-selection)", n)
	}
	d.mu.Lock()
	encrypts := d.encrypts
	d.mu.Unlock()
	if encrypts != 3 {
		t.Fatalf("the proxy saw %d encrypts, want 3: one, the refused two, two again", encrypts)
	}
}

// "sent": the request was written before the tunnel failed and the node may
// have used the nonce. A POST is not sent again (rule 3).
func TestProxySentFailureIsNotResent(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	d.set(func(d *fakeDaemon) { d.sentFail = true })
	_, err := c.Encrypt(ctx, []byte("x"), "ch")
	if !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "after the request was sent") {
		t.Fatalf("Encrypt: %v, want ErrTunnelUnavailable naming a sent request", err)
	}
	d.mu.Lock()
	encrypts := d.encrypts
	d.mu.Unlock()
	if encrypts != 1 {
		t.Fatalf("the proxy saw %d encrypts, want 1", encrypts)
	}
}

// The daemon's proxies want its token (CULPER-467, CulperLink audit B2-3):
// every Data Plane request presents it, a daemon that reports none is
// refused before anything crosses its proxy, and a 407 — a restarted
// daemon's new token — sent nothing and is answered by reading the token
// again.
func TestProxyToken(t *testing.T) {
	skipWithoutUnixSockets(t)
	ctx := context.Background()

	t.Run("presented", func(t *testing.T) {
		cp := newFakeCP(t)
		d := newFakeDaemon(t, "0.2.0")
		c := tunnelClient(t, cp, d)
		if _, err := c.Encrypt(ctx, []byte("x"), "ch"); err != nil {
			t.Fatal(err)
		}
		d.mu.Lock()
		refused := d.refused
		d.mu.Unlock()
		if refused != 0 {
			t.Fatalf("the proxy refused %d requests", refused)
		}
		st := c.CurrentSession()
		if strings.Contains(fmt.Sprintf("%+v", st), fakeProxyToken) {
			t.Fatal("the proxy token is in the session the library returns")
		}
	})
	t.Run("a daemon without one", func(t *testing.T) {
		cp := newFakeCP(t)
		d := newFakeDaemon(t, "0.2.0")
		d.set(func(d *fakeDaemon) { d.proxyToken = "" })
		c := tunnelClient(t, cp, d)
		_, err := c.Encrypt(ctx, []byte("x"), "ch")
		if !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "no proxy token") {
			t.Fatalf("Encrypt: %v, want ErrTunnelUnavailable naming the missing token", err)
		}
		d.mu.Lock()
		encrypts, refused := d.encrypts, d.refused
		d.mu.Unlock()
		if encrypts != 0 || refused != 0 {
			t.Fatalf("something crossed the proxy: %d encrypts, %d refused", encrypts, refused)
		}
		if ops := d.opList(); ops[len(ops)-1] != "disconnect" {
			t.Fatalf("the tunnel was left up: %v", ops)
		}
	})
	t.Run("a stale one is read again", func(t *testing.T) {
		cp := newFakeCP(t)
		d := newFakeDaemon(t, "0.2.0")
		c := tunnelClient(t, cp, d)
		if _, err := c.Encrypt(ctx, []byte("one"), "ch"); err != nil {
			t.Fatal(err)
		}
		d.set(func(d *fakeDaemon) { d.proxyToken = strings.Repeat("a1", 32) })
		if _, err := c.Encrypt(ctx, []byte("two"), "ch"); err != nil {
			t.Fatalf("Encrypt after the token changed: %v", err)
		}
		d.mu.Lock()
		refused, encrypts := d.refused, d.encrypts
		d.mu.Unlock()
		if refused != 1 || encrypts != 2 {
			t.Fatalf("refused %d, encrypts %d; want 1 and 2", refused, encrypts)
		}
	})
}

func TestTunnelThatStaysDownIsTunnelUnavailable(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	d.set(func(d *fakeDaemon) { d.httpAddr = "127.0.0.1:1" }) // nothing listens
	c := tunnelClient(t, cp, d, func(o *Options) { o.MaxRetries = Retries(1) })
	_, err := c.Encrypt(context.Background(), []byte("x"), "ch")
	if !errors.Is(err, ErrTunnelUnavailable) {
		t.Fatalf("Encrypt: %v, want ErrTunnelUnavailable", err)
	}
	if strings.Contains(err.Error(), "10.200.0.1") || strings.Contains(err.Error(), "127.0.0.1") || addressLike.MatchString(err.Error()) {
		t.Fatalf("the error names an address: %v", err)
	}
}

// The daemon's own reply text reaches the caller only when it names no
// address (G-26). An older daemon replied to a failed connect with the raw
// transport error, which carried the node's handshake URL; this one is a
// dial error carrying 127.0.0.1:1.
func TestDaemonRepliesNamingAnAddressAreWithheld(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	d.set(func(d *fakeDaemon) {
		d.connectErr = `connect: Post "https://127.0.0.1:1/sdk/v1/tunnel/handshake": dial tcp 127.0.0.1:1: connect: connection refused`
	})
	c := tunnelClient(t, cp, d)
	err := c.Connect(context.Background())
	if !errors.Is(err, ErrTunnelUnavailable) {
		t.Fatalf("Connect: %v, want ErrTunnelUnavailable", err)
	}
	if addressLike.MatchString(err.Error()) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the error names an address or a port: %q", err.Error())
	}
	// A class with no address in it is passed on: it is the useful part.
	d.set(func(d *fakeDaemon) { d.connectErr = "connect: pin_mismatch" })
	err = tunnelClient(t, cp, d).Connect(context.Background())
	if !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "pin_mismatch") {
		t.Fatalf("Connect: %v, want ErrTunnelUnavailable naming pin_mismatch", err)
	}
}

// A sent encrypt that timed out through the daemon is the timeout itself, not
// ErrTunnelUnavailable, it is not sent again (retry.go, rule 3), and its text
// names no address.
func TestTunnelledTimeoutIsATimeoutAndNotResent(t *testing.T) {
	skipWithoutUnixSockets(t)
	countPauses(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d, func(o *Options) { o.MaxRetries = Retries(2); o.Timeout = time.Second })
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.set(func(d *fakeDaemon) { d.hold, d.encrypts = 3*time.Second, 0 })
	_, err := c.Encrypt(context.Background(), []byte("p"), "ch")
	if err == nil || !isTimeout(err) || errors.Is(err, ErrTunnelUnavailable) {
		t.Fatalf("Encrypt = %v, want a timeout that is not ErrTunnelUnavailable", err)
	}
	if addressLike.MatchString(err.Error()) {
		t.Fatalf("the error names an address or a port: %q", err.Error())
	}
	d.mu.Lock()
	n := d.encrypts
	d.mu.Unlock()
	if n != 1 {
		t.Fatalf("encrypts the node received = %d, want 1", n)
	}
}

// GATEWAY_SELECTION_NOT_CONFIGURED is the installation's deployment, not
// the organisation's policy: ErrSelectionNotConfigured, never the sovereign
// error, and selection is asked once (G-32).
func TestSelectionNotConfiguredIsItsOwnError(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/sdk/v1/gateways/select" {
			apiErr(w, http.StatusServiceUnavailable, "GATEWAY_SELECTION_NOT_CONFIGURED", "gateway selection is not configured on this installation")
			return true
		}
		return false
	})
	err := tunnelClient(t, cp, d, func(o *Options) { o.MaxRetries = Retries(2) }).Connect(context.Background())
	if !errors.Is(err, ErrSelectionNotConfigured) || errors.Is(err, ErrSovereignNodeUnavailable) {
		t.Fatalf("Connect: %v, want ErrSelectionNotConfigured and not ErrSovereignNodeUnavailable", err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("the service's 503 is not reachable: %v", err)
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 1 {
		t.Fatalf("selections = %d, want 1", n)
	}
}

// A token rotation is followed, in the same call, by a lease renewal with
// the new data_token; a refusal there is the caller's error.
func TestTokenRotationRenewsTheLease(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	cp.ttl = time.Minute // every call is inside the refresh window
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Encrypt(ctx, []byte("x"), "ch"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(d.opList(), "renew") {
		t.Fatalf("ops = %v, want a renew after the rotation", d.opList())
	}
	d.mu.Lock()
	last := d.tokens[len(d.tokens)-1]
	d.mu.Unlock()
	if last != c.session.dataTokenValue() {
		t.Fatalf("daemon holds %q, client %q", last, c.session.dataTokenValue())
	}

	d.set(func(d *fakeDaemon) { d.renewErr = "lease refused" })
	if _, err := c.Encrypt(ctx, []byte("x"), "ch"); !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "lease refused") {
		t.Fatalf("Encrypt with the lease refused: %v", err)
	}
}

func TestTunnelStatusAsksTheDaemon(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	ctx := context.Background()
	if st, _ := c.TunnelStatus(ctx); st.State != "down" {
		t.Fatalf("before connect: %q", st.State)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	d.set(func(d *fakeDaemon) { d.connected = false })
	st, _ := c.TunnelStatus(ctx)
	if st.State != "down" || st.Gateway != nil {
		t.Fatalf("after the daemon went down: %+v", st)
	}
	off := offClient(t, cp)
	if st, _ := off.TunnelStatus(ctx); st.State != "off" || st.Mode != TunnelOff {
		t.Fatalf("TunnelOff status = %+v", st)
	}
}

// ---------------------------------------------------------------------------
// Finding and starting the daemon: this test binary, re-executed as the fake.
// ---------------------------------------------------------------------------

// fakeDaemonOnPath writes an executable named culperlink-tunnel that runs
// this test binary as the fake daemon, and returns its directory.
func fakeDaemonOnPath(t *testing.T, version, record string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		envFakeDaemon + "=1 " + envFakeVer + "='" + version + "' " + envFakeRecord + "='" + record + "' exec '" + self + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, DaemonName), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable in a test's temp dir
		t.Fatal(err)
	}
	return dir
}

// shortRuntimeDir keeps the spawned daemon's socket path under the Unix
// limit, which a test's temp directory can overrun.
func shortRuntimeDir(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "clrt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// Found on PATH, started with -exit-with-parent and a private control
// directory, and stopped by Close.
func TestSpawnedDaemonFromPathIsStoppedByClose(t *testing.T) {
	skipWithoutUnixSockets(t)
	shortRuntimeDir(t)
	record := filepath.Join(t.TempDir(), "args")
	t.Setenv("PATH", fakeDaemonOnPath(t, "0.2.0", record)+string(os.PathListSeparator)+os.Getenv("PATH"))
	cp := newFakeCP(t)
	c, err := NewClient(Options{
		APIKey: testAPIKey, Endpoint: cp.srv.URL,
		TLS: TLSConfig{CACertFile: cp.caPEMFile(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sealed, err := c.Encrypt(ctx, []byte("spawned"), "ch")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := c.Decrypt(ctx, sealed, "ch"); err != nil || string(out) != "spawned" {
		t.Fatalf("Decrypt = %q, %v", out, err)
	}
	st := c.CurrentSession().Tunnel
	pid := st.DaemonPID
	if pid <= 0 || !pidAlive(pid) {
		t.Fatalf("DaemonPID = %d", pid)
	}
	args, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-exit-with-parent", "-socks 127.0.0.1:0", "-http 127.0.0.1:0", "-log-level warn", "dirmode=700"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("daemon started with %q; missing %q", args, want)
		}
	}
	workdir := filepath.Dir(c.tunnel.daemon.socket)

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for pidAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("daemon %d still running after Close", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(workdir); !os.IsNotExist(err) {
		t.Fatalf("control directory %s survived Close: %v", workdir, err)
	}
}

func TestSpawnedDaemonOutsideTheRangeIsStopped(t *testing.T) {
	skipWithoutUnixSockets(t)
	shortRuntimeDir(t)
	dir := fakeDaemonOnPath(t, "0.1.0", "")
	cp := newFakeCP(t)
	c, err := NewClient(Options{
		APIKey: testAPIKey, Endpoint: cp.srv.URL,
		TLS:    TLSConfig{CACertFile: cp.caPEMFile(t)},
		Tunnel: TunnelOptions{DaemonPath: filepath.Join(dir, DaemonName)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(context.Background()); !errors.Is(err, ErrTunnelDaemonIncompatible) {
		t.Fatalf("Connect: %v", err)
	}
	entries, _ := os.ReadDir(os.Getenv("XDG_RUNTIME_DIR"))
	if len(entries) != 0 {
		t.Fatalf("a refused daemon left %d entries in the runtime dir", len(entries))
	}
}

// Without a daemon the error names every place searched, in order, before
// any gateway is selected.
func TestMissingDaemonNamesTheSearchOrder(t *testing.T) {
	skipWithoutUnixSockets(t)
	t.Setenv("PATH", t.TempDir())
	cp := newFakeCP(t)
	c, err := NewClient(Options{APIKey: testAPIKey, Endpoint: cp.srv.URL, TLS: TLSConfig{CACertFile: cp.caPEMFile(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, err = c.Encrypt(context.Background(), []byte("x"), "ch")
	if !errors.Is(err, ErrTunnelDaemonNotFound) || !errors.Is(err, ErrTunnelUnavailable) {
		t.Fatalf("Encrypt: %v, want ErrTunnelDaemonNotFound", err)
	}
	for _, want := range []string{"1. Options.Tunnel.DaemonPath", "2. PATH", "bin/culperlink-tunnel", "DaemonSocket", "TunnelOff"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message lacks %q: %v", want, err)
		}
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 0 {
		t.Fatalf("selected %d times with no daemon", n)
	}

	c2, _ := NewClient(Options{APIKey: testAPIKey, Endpoint: cp.srv.URL, TLS: TLSConfig{CACertFile: cp.caPEMFile(t)}, Tunnel: TunnelOptions{DaemonPath: filepath.Join(t.TempDir(), "nope")}})
	defer func() { _ = c2.Close() }()
	if err := c2.Connect(context.Background()); !errors.Is(err, ErrTunnelDaemonNotFound) || !strings.Contains(err.Error(), "Options.Tunnel.DaemonPath") {
		t.Fatalf("bad DaemonPath: %v", err)
	}
}

// TestPolicyIPv6ReachesTheDaemon is CULPER-460 G-4: the policy's ipv6 flag is
// carried to the daemon. Without it a full+IPv6 organisation's node offers
// ::/0, the daemon plans IPv4 only and refuses the offer, and the client
// cannot connect.
func TestPolicyIPv6ReachesTheDaemon(t *testing.T) {
	skipWithoutUnixSockets(t)
	tests := []struct {
		name   string
		policy map[string]any
		want   bool
	}{
		{"full with ipv6", map[string]any{"mode": "full", "dns": map[string]any{"mode": "host"}, "ipv6": true}, true},
		{"prefixes with ipv6", map[string]any{"mode": "prefixes", "prefixes": []string{"10.50.0.0/16", "fd00:50::/32"}, "dns": map[string]any{"mode": "host"}, "ipv6": true}, true},
		{"full, ipv6 absent", map[string]any{"mode": "full", "dns": map[string]any{"mode": "host"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := newFakeCP(t)
			cp.policy = tc.policy
			d := newFakeDaemon(t, "0.2.0")
			c := tunnelClient(t, cp, d)
			if err := c.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			d.mu.Lock()
			p, _ := d.connectReqs[0]["policy"].(map[string]any)
			d.mu.Unlock()
			if got, ok := p["ipv6"].(bool); !ok || got != tc.want {
				t.Fatalf("policy handed to the daemon = %v, want ipv6=%v", p, tc.want)
			}
		})
	}
}

// A payload request the node answers 409 — the tunnel changed tenant
// (CULPER-467, decision 38) — was refused before any handler ran. The client
// tears its tunnel down, connects afresh with the current data_token and
// sends the call once more (CULPER-469). A second 409 is the caller's.
func TestATenantConflictReconnectsOnceAndSendsAgain(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	d.set(func(d *fakeDaemon) { d.conflicts = 1 })
	if _, err := c.Encrypt(ctx, []byte("p"), "ch"); err != nil {
		t.Fatalf("Encrypt after a tenant conflict: %v", err)
	}
	d.mu.Lock()
	encrypts := d.encrypts
	d.mu.Unlock()
	if encrypts != 2 {
		t.Fatalf("the node saw %d encrypts, want 2", encrypts)
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 2 {
		t.Fatalf("selections = %d, want 2", n)
	}
	var connects, disconnectBeforeLast int
	list := d.opList()
	last := -1
	for i, op := range list {
		if op == "connect" {
			connects++
			last = i
		}
	}
	for i, op := range list {
		if op == "disconnect" && i < last {
			disconnectBeforeLast++
		}
	}
	if connects != 2 || disconnectBeforeLast == 0 {
		t.Fatalf("ops = %v: want a disconnect before the second connect", list)
	}
}

func TestASecondTenantConflictIsTheCallers(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)
	d := newFakeDaemon(t, "0.2.0")
	c := tunnelClient(t, cp, d)
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	d.set(func(d *fakeDaemon) { d.conflicts = 5 })
	_, err := c.Encrypt(ctx, []byte("p"), "ch")
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusConflict || api.Code != "CONFLICT" {
		t.Fatalf("err = %v, want the node's 409", err)
	}
	d.mu.Lock()
	encrypts := d.encrypts
	d.mu.Unlock()
	if encrypts != 2 {
		t.Fatalf("the node saw %d encrypts, want 2: once, not a loop", encrypts)
	}
}
