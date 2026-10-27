package culperlink

// daemon_e2e_test.go — this library against the REAL culperlink-tunnel
// daemon from a CulperLink release package, rather than the fake in
// fakes_test.go. It proves the half of the contract a unit test cannot: that
// the daemon this library will meet accepts the flags it is started with,
// answers the control protocol in the shape parsed here, reports a version
// inside [DaemonVersionMin, DaemonVersionMax), carries a connect refusal back
// as its own error, and exits when this library closes.
//
// It runs only when CULPERLINK_TUNNEL_BIN names the daemon executable (the
// CI workflow's e2e job downloads one from a release; locally, build it
// from the CulperLink release package or point at bin/culperlink-tunnel-*).
// The full round trip through a node needs an installation and is not run
// here; the CulperLink core repository runs it against this library.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRealDaemonSpeaksTheControlProtocol(t *testing.T) {
	bin := os.Getenv("CULPERLINK_TUNNEL_BIN")
	if bin == "" {
		t.Skip("CULPERLINK_TUNNEL_BIN is not set: the real daemon comes from a release package")
	}
	skipWithoutUnixSockets(t)
	shortRuntimeDir(t)
	cp := newFakeCP(t)
	c1 := candidate(fakeNodeID, "US", "us-east-1")
	c1["handshake_endpoint"] = "https://127.0.0.1:1" // nothing listens: the handshake is refused
	c1["wireguard_endpoint"] = "127.0.0.1:1"
	cp.candidates = []map[string]any{c1}
	c, err := NewClient(Options{
		APIKey: testAPIKey, Endpoint: cp.srv.URL,
		TLS:    TLSConfig{CACertFile: cp.caPEMFile(t)},
		Tunnel: TunnelOptions{DaemonPath: bin, ConnectTimeout: time.Minute, DaemonLogLevel: "error"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = c.Connect(ctx)
	if !errors.Is(err, ErrTunnelUnavailable) || errors.Is(err, ErrTunnelDaemonIncompatible) || errors.Is(err, ErrTunnelDaemonNotFound) {
		t.Fatalf("Connect to an unreachable node: %v, want the daemon's own refusal", err)
	}
	if strings.Contains(err.Error(), "malformed reply") || strings.Contains(err.Error(), "control socket") {
		t.Fatalf("the daemon did not answer in the protocol's shape: %v", err)
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 1 {
		t.Fatalf("selections = %d, want 1", n)
	}
	st, _ := c.TunnelStatus(ctx)
	pid := st.DaemonPID
	if pid <= 0 || !pidAlive(pid) || st.State != "down" {
		t.Fatalf("after a refused connect: %+v", st)
	}
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
}
