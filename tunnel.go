package culperlink

// tunnel.go — the tunnel as this library's Data Plane transport, through the
// culperlink-tunnel daemon (CULPER-452; the Python and TypeScript libraries'
// CULPER-414 design, in Go). The package doc's "The daemon" section has the
// lifecycle; this file is its implementation:
//
//   - locateDaemon: the search order, and an error naming every place looked;
//   - spawnDaemon: a private directory, -exit-with-parent, stdin held;
//   - daemon.call: one JSON request and one JSON reply per connection;
//   - checkDaemonVersion: the range, before any token is handed over;
//   - tunnelState: select → connect → proxy, renew, status, close.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DaemonName is the daemon's executable name, as looked up on PATH.
const DaemonName = "culperlink-tunnel"

// The daemon versions this library drives: [DaemonVersionMin,
// DaemonVersionMax), compared on the dotted numeric triple. The daemon
// reports its release version on every control reply. The range is this
// library's statement of the control protocol it speaks, and it is the same
// range the Python and TypeScript libraries of the same release carry. It is
// moved by hand: the lower bound is the oldest daemon whose control protocol
// this library speaks, a claim someone makes on purpose.
const (
	DaemonVersionMin = "0.2.0"
	DaemonVersionMax = "0.3.0"
)

// daemonPathOption is the option that names the daemon; quoted in errors.
const daemonPathOption = "Options.Tunnel.DaemonPath"

// proxyUnreachable is the daemon proxy's own reply body when the tunnel
// cannot carry a request (a 502). Recognised so a tunnel that went down
// between calls is re-established rather than reported as the node's 502.
const proxyUnreachable = "upstream unreachable through the tunnel"

// TunnelMode selects how Data Plane calls reach the node.
type TunnelMode string

const (
	// TunnelNetstack has the daemon run the WireGuard tunnel over a
	// userspace TCP/IP stack: no device on the host, no privilege, and only
	// this client's traffic rides it. The default.
	TunnelNetstack TunnelMode = "netstack"
	// TunnelSystem has the daemon create a real TUN device and install the
	// policy's routes. The daemon then needs CAP_NET_ADMIN (Linux) or root
	// (macOS), and refuses rather than falling back.
	TunnelSystem TunnelMode = "system"
	// TunnelOff is the HTTPS-only client: every call goes to
	// Options.Endpoint, no candidate list is requested and no daemon is
	// involved. For an installation with no Data Plane node, and for
	// Windows. A tunnel-serving installation refuses payload calls on its
	// public address, so TunnelOff against one fails with a 404.
	TunnelOff TunnelMode = "off"
)

// TunnelOptions configures the Data Plane transport. The zero value is
// TunnelNetstack with a daemon found on PATH.
type TunnelOptions struct {
	// Mode is TunnelNetstack (default), TunnelSystem or TunnelOff.
	Mode TunnelMode

	// CUIMarking is sent with gateway selection and decides the constraints
	// and geofence the Control Plane applies (and this client re-applies).
	CUIMarking CUIMarking

	// Country and Region are the client's position, disclosed at the
	// caller's discretion to order candidates by proximity. They never
	// widen the list. Empty discloses nothing.
	Country string
	Region  string

	// MaxCandidates caps the list; zero means the service default.
	MaxCandidates int

	// RootCAsPEM anchors the node's handshake listener. Empty uses the CA
	// bundle Options.TLS names, or the daemon's system pool when it names
	// none. The SPKI pin from the candidate list is checked either way.
	RootCAsPEM []byte

	// DaemonPath is an explicit path to the culperlink-tunnel executable:
	// the first place looked.
	DaemonPath string

	// DaemonSocket is the control socket of a daemon already running. When
	// set nothing is started, and Close leaves the daemon running (it
	// disconnects the tunnel this client connected).
	DaemonSocket string

	// DaemonLogLevel is the -log-level of a daemon this client starts:
	// "debug", "info", "warn" (default) or "error". Its stderr is this
	// process's.
	DaemonLogLevel string

	// ConnectTimeout bounds the daemon's walk of the candidate list.
	// Defaults to two minutes.
	ConnectTimeout time.Duration

	// KillSwitch, when set, overrides the daemon's kill-switch setting.
	KillSwitch *bool
}

// TunnelStatus is the tunnel's state.
type TunnelStatus struct {
	// Mode is the configured mode.
	Mode TunnelMode
	// State is "off" in TunnelOff; otherwise the daemon's: "down",
	// "connecting", "up" or "degraded".
	State string
	// Gateway is the node the tunnel is established to, as selection
	// offered it; nil when no tunnel is up.
	Gateway *GatewayDescriptor
	// ClientTunnelIP and NodeTunnelIP are the addresses inside the tunnel.
	ClientTunnelIP string
	NodeTunnelIP   string
	// AllowedIPs is what the policy routes through the tunnel.
	AllowedIPs []string
	// LeaseExpiresAt is when the lease lapses unless renewed.
	LeaseExpiresAt time.Time
	// LastHandshake is WireGuard's last handshake with the node.
	LastHandshake time.Time
	// Reconnects counts re-establishments on this tunnel.
	Reconnects int
	// LastError is the class of the last error the daemon recorded.
	LastError string
	// DaemonPID is the process id of a daemon this client started; zero
	// when it started none (TunnelOff, DaemonSocket, or not yet connected).
	DaemonPID int
}

func offStatus() *TunnelStatus { return &TunnelStatus{Mode: TunnelOff, State: "off"} }

// TunnelStatus asks the daemon for the tunnel's state now. Without a daemon
// (TunnelOff, or before the first connection) it reports what is known.
func (c *Client) TunnelStatus(ctx context.Context) (*TunnelStatus, error) {
	if c.tunnel == nil {
		return offStatus(), nil
	}
	return c.tunnel.refreshStatus(ctx), nil
}

// ============================================================================
// Finding, starting and talking to the daemon
// ============================================================================

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return st.Mode().Perm()&0o111 != 0
}

// locateDaemon finds the daemon by the documented search order, or returns
// ErrTunnelDaemonNotFound naming every place looked.
func locateDaemon(explicit string) (string, error) {
	if explicit != "" {
		if isExecutable(explicit) {
			return explicit, nil
		}
		return "", &tunnelError{kind: ErrTunnelDaemonNotFound, msg: fmt.Sprintf(
			"culperlink: %s = %q is not an executable file", daemonPathOption, explicit)}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if p := filepath.Join(dir, DaemonName); isExecutable(p) {
			return p, nil
		}
	}
	return "", &tunnelError{kind: ErrTunnelDaemonNotFound, msg: fmt.Sprintf(
		"culperlink: the %[1]s daemon was not found. Searched, in order: "+
			"1. %[2]s (not set); 2. PATH (no %[1]s). "+
			"Install the daemon for %[3]s/%[4]s from the CulperLink release package (bin/%[1]s-%[3]s-%[4]s) on PATH as %[1]s, or set %[2]s to it; "+
			"set Options.Tunnel.DaemonSocket to the control socket of a daemon already running; "+
			"or set Options.Tunnel.Mode = TunnelOff for an HTTPS-only installation",
		DaemonName, daemonPathOption, runtime.GOOS, runtime.GOARCH)}
}

// daemonReply is the control protocol's reply (cmd/culperlink-tunnel).
type daemonReply struct {
	OK      bool          `json:"ok"`
	Error   string        `json:"error,omitempty"`
	Status  *daemonStatus `json:"status,omitempty"`
	Version any           `json:"version"`
}

type daemonStatus struct {
	State          string   `json:"state"`
	Mode           string   `json:"mode"`
	CandidateID    string   `json:"candidate_id"`
	ClientTunnelIP string   `json:"client_tunnel_ip"`
	NodeTunnelIP   string   `json:"node_tunnel_ip"`
	AllowedIPs     []string `json:"allowed_ips"`
	LeaseExpiresAt string   `json:"lease_expires_at"`
	LastHandshake  string   `json:"last_handshake"`
	Reconnects     int      `json:"reconnects"`
	LastError      string   `json:"last_error"`
	SocksAddr      string   `json:"socks_addr"`
	HTTPAddr       string   `json:"http_addr"`
}

// daemonCandidate is a candidate in the daemon's request shape: the four
// public tunnel facts and the id.
type daemonCandidate struct {
	ID                 string `json:"id"`
	HandshakeEndpoint  string `json:"handshake_endpoint"`
	WireGuardEndpoint  string `json:"wireguard_endpoint"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
	SPKIPin            string `json:"spki_pin"`
}

// daemonPolicy is the traffic policy in the daemon's request shape.
type daemonPolicy struct {
	Mode             string   `json:"mode"`
	Prefixes         []string `json:"prefixes"`
	DNSThroughTunnel bool     `json:"dns_through_tunnel"`
	Resolvers        []string `json:"resolvers"`
	IPv6             bool     `json:"ipv6"`
}

type daemonConnectRequest struct {
	Op         string            `json:"op"`
	Mode       string            `json:"mode"`
	Candidates []daemonCandidate `json:"candidates"`
	DataToken  string            `json:"data_token"`
	Policy     *daemonPolicy     `json:"policy,omitempty"`
	RootCAsPEM string            `json:"root_cas_pem,omitempty"`
	Tunnel     *daemonKnobs      `json:"tunnel,omitempty"`
}

type daemonKnobs struct {
	KillSwitch *bool `json:"kill_switch,omitempty"`
}

// daemon is one daemon: its control socket and, if this client started it,
// the process.
type daemon struct {
	socket  string
	cmd     *exec.Cmd      // nil for a daemon named by DaemonSocket
	stdin   io.WriteCloser // the pipe the daemon watches
	workdir string
	exited  chan struct{} // closed when a started daemon exits
}

func (d *daemon) spawned() bool { return d.cmd != nil }

func (d *daemon) pid() int {
	if d.cmd == nil || d.cmd.Process == nil {
		return 0
	}
	return d.cmd.Process.Pid
}

func (d *daemon) alive() bool {
	if d.exited == nil {
		return true
	}
	select {
	case <-d.exited:
		return false
	default:
		return true
	}
}

// call sends one request and reads one reply, on its own connection.
func (d *daemon) call(ctx context.Context, req any, timeout time.Duration) (*daemonReply, error) {
	op := opOf(req)
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	var dialer net.Dialer
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := dialer.DialContext(dctx, "unix", d.socket)
	if err != nil {
		return nil, tunnelUnavailable("cannot reach the %s control socket (%s)", DaemonName, errClass(err))
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	// The reply is awaited even if ctx ends first only up to the deadline;
	// closing the connection on cancellation unblocks the read.
	stop := context.AfterFunc(dctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("culperlink: marshal daemon request: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, tunnelUnavailable("cannot reach the %s control socket (%s)", DaemonName, errClass(err))
	}
	raw, err := bufio.NewReaderSize(conn, 64*1024).ReadBytes('\n')
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, tunnelUnavailable("the daemon did not answer %q within %s", op, timeout.Round(time.Second))
		}
		if errors.Is(err, io.EOF) {
			return nil, tunnelUnavailable("the daemon closed the control connection without a reply (it admits only its own user or root)")
		}
		return nil, tunnelUnavailable("cannot reach the %s control socket (%s)", DaemonName, errClass(err))
	}
	var rep daemonReply
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rep); err != nil {
		return nil, tunnelUnavailable("malformed reply from the daemon")
	}
	return &rep, nil
}

func opOf(req any) string {
	switch r := req.(type) {
	case map[string]string:
		return r["op"]
	case *daemonConnectRequest:
		return r.Op
	}
	return ""
}

// stop stops a started daemon — close the pipe it watches, then insist —
// and removes its private directory.
func (d *daemon) stop() {
	if d.cmd != nil && d.cmd.Process != nil {
		if d.stdin != nil {
			_ = d.stdin.Close()
		}
		if !waitExit(d.exited, 3*time.Second) {
			_ = d.cmd.Process.Signal(syscall.SIGTERM)
			if !waitExit(d.exited, 2*time.Second) {
				_ = d.cmd.Process.Kill()
				<-d.exited
			}
		}
	}
	if d.workdir != "" {
		_ = os.RemoveAll(d.workdir)
	}
}

func waitExit(ch chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	}
}

// spawnDaemon starts the daemon with a control socket in a fresh directory
// only this user can read, proxies on kernel-chosen loopback ports, and
// -exit-with-parent over a pipe this process holds.
func spawnDaemon(ctx context.Context, path, logLevel string) (*daemon, error) {
	if runtime.GOOS == "windows" {
		return nil, tunnelUnavailable("the %s control transport is not implemented on windows (a named pipe); "+
			"set Options.Tunnel.Mode = TunnelOff for an HTTPS-only installation", DaemonName)
	}
	// Unix socket paths are limited to about 104 bytes, so the directory is
	// short: XDG_RUNTIME_DIR when set, the temp directory otherwise.
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	workdir, err := os.MkdirTemp(base, "culperlink-tunnel-")
	if err != nil {
		return nil, tunnelUnavailable("cannot create the daemon's control directory (%s)", errClass(err))
	}
	if err := os.Chmod(workdir, 0o700); err != nil {
		_ = os.RemoveAll(workdir)
		return nil, tunnelUnavailable("cannot restrict the daemon's control directory (%s)", errClass(err))
	}
	sock := filepath.Join(workdir, "control.sock")

	// Not CommandContext: the daemon's life is the Client's, not ctx's.
	cmd := exec.Command(path, // #nosec G204 -- the daemon path is the caller's own configuration or PATH
		"-socket", sock, "-socks", "127.0.0.1:0", "-http", "127.0.0.1:0",
		"-exit-with-parent", "-log-level", logLevel)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = os.RemoveAll(workdir)
		return nil, tunnelUnavailable("cannot start %s (%s)", path, errClass(err))
	}
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(workdir)
		return nil, tunnelUnavailable("could not start %s (%s)", path, errClass(err))
	}
	d := &daemon{socket: sock, cmd: cmd, stdin: stdin, workdir: workdir, exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(d.exited)
	}()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if !d.alive() {
			code := -1
			if cmd.ProcessState != nil {
				code = cmd.ProcessState.ExitCode()
			}
			d.stop()
			return nil, tunnelUnavailable("%s exited with status %d before its control socket came up", DaemonName, code)
		}
		if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
			_ = c.Close()
			return d, nil
		}
		if time.Now().After(deadline) {
			d.stop()
			return nil, tunnelUnavailable("%s did not open its control socket", DaemonName)
		}
		if err := sleepCtx(ctx, 20*time.Millisecond); err != nil {
			d.stop()
			return nil, err
		}
	}
}

// parseVersion reads "X.Y.Z", tolerating a leading "v" and a pre-release or
// build suffix.
func parseVersion(v any) ([3]int, bool) {
	var t [3]int
	s, ok := v.(string)
	if !ok || s == "" {
		return t, false
	}
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return t, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || strings.TrimLeft(p, "0123456789") != "" {
			return t, false
		}
		t[i] = n
	}
	return t, true
}

func cmpVersion(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return 0
}

// checkDaemonVersion is ErrTunnelDaemonIncompatible for a daemon outside
// [DaemonVersionMin, DaemonVersionMax), naming both versions.
func checkDaemonVersion(reported any) error {
	lo, _ := parseVersion(DaemonVersionMin)
	hi, _ := parseVersion(DaemonVersionMax)
	wants := fmt.Sprintf("%s >= %s, < %s", DaemonName, DaemonVersionMin, DaemonVersionMax)
	got, ok := parseVersion(reported)
	if !ok {
		shown, _ := json.Marshal(reported)
		return &tunnelError{kind: ErrTunnelDaemonIncompatible, msg: fmt.Sprintf(
			"culperlink: the daemon reported no usable version (%s; it predates the version handshake); "+
				"this library, culperlink-go %s, needs %s", shown, Version, wants)}
	}
	if cmpVersion(got, lo) < 0 || cmpVersion(got, hi) >= 0 {
		return &tunnelError{kind: ErrTunnelDaemonIncompatible, msg: fmt.Sprintf(
			"culperlink: %s %v is outside the range this library, culperlink-go %s, drives (%s); "+
				"upgrade the daemon or the SDK so the two match", DaemonName, reported, Version, wants)}
	}
	return nil
}

// isLoopbackHostPort is true for 127.0.0.0/8:port and [::1]:port only.
func isLoopbackHostPort(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	return err == nil && ap.Addr().Unmap().IsLoopback() && ap.Port() != 0
}

// ============================================================================
// The tunnel as the client's Data Plane transport
// ============================================================================

// tunnelState is the client's tunnel: the daemon, the node it is on, and the
// HTTP client that sends through the daemon's proxy.
type tunnelState struct {
	opts    TunnelOptions
	roots   []byte
	timeout time.Duration

	// connectMu serialises select-and-establish so concurrent first calls
	// produce one tunnel. renewLease and status never take it, because
	// selection's own Control Plane call may rotate the token pair and
	// renew the lease while it is held.
	connectMu sync.Mutex

	mu      sync.Mutex
	daemon  *daemon
	gateway *GatewayDescriptor
	tgt     *target
	last    daemonStatus
	closed  bool
}

func newTunnelState(opts TunnelOptions, roots []byte, timeout time.Duration) *tunnelState {
	if opts.DaemonLogLevel == "" {
		opts.DaemonLogLevel = "warn"
	}
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = 2 * time.Minute
	}
	return &tunnelState{opts: opts, roots: roots, timeout: timeout}
}

// live is the current target, or nil when there is none or the daemon last
// said the tunnel is down.
func (ts *tunnelState) live() *target {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.tgt == nil || ts.last.State == "" || ts.last.State == "down" {
		return nil
	}
	return ts.tgt
}

// ensure returns a live tunnel's target, establishing one if needed.
func (ts *tunnelState) ensure(ctx context.Context, c *Client) (target, error) {
	if t := ts.live(); t != nil {
		return *t, nil
	}
	ts.connectMu.Lock()
	defer ts.connectMu.Unlock()
	if t := ts.live(); t != nil {
		return *t, nil
	}
	t, err := ts.establish(ctx, c)
	if err != nil {
		return target{}, err
	}
	return *t, nil
}

// daemonHandle is the daemon, started or reached and version-checked. A
// started daemon that died is replaced.
func (ts *tunnelState) daemonHandle(ctx context.Context) (*daemon, error) {
	ts.mu.Lock()
	d := ts.daemon
	closed := ts.closed
	ts.mu.Unlock()
	if closed {
		return nil, ErrClientClosed
	}
	if d != nil && d.alive() {
		return d, nil
	}
	if d != nil {
		d.stop()
		ts.mu.Lock()
		ts.daemon = nil
		ts.mu.Unlock()
	}
	if ts.opts.DaemonSocket != "" {
		d = &daemon{socket: ts.opts.DaemonSocket}
	} else {
		path, err := locateDaemon(ts.opts.DaemonPath)
		if err != nil {
			return nil, err
		}
		if d, err = spawnDaemon(ctx, path, ts.opts.DaemonLogLevel); err != nil {
			return nil, err
		}
	}
	rep, err := d.call(ctx, map[string]string{"op": "status"}, 15*time.Second)
	if err == nil {
		err = checkDaemonVersion(rep.Version)
	}
	if err != nil {
		if d.spawned() {
			d.stop()
		}
		return nil, err
	}
	ts.mu.Lock()
	ts.daemon = d
	ts.mu.Unlock()
	return d, nil
}

func (ts *tunnelState) establish(ctx context.Context, c *Client) (*target, error) {
	ts.dropTransport()
	// The daemon first: with none to hand the list to, nothing is selected.
	d, err := ts.daemonHandle(ctx)
	if err != nil {
		return nil, err
	}
	candidates, policy, err := c.selectGateways(ctx)
	if err != nil {
		return nil, err
	}
	req := &daemonConnectRequest{
		Op:        "connect",
		Mode:      string(ts.opts.Mode),
		DataToken: c.session.dataTokenValue(),
		Policy:    policy,
	}
	for _, g := range candidates {
		req.Candidates = append(req.Candidates, daemonCandidate{
			ID: g.ID, HandshakeEndpoint: g.HandshakeEndpoint, WireGuardEndpoint: g.WireGuardEndpoint,
			WireGuardPublicKey: g.WireGuardPublicKey, SPKIPin: g.SPKIPin,
		})
	}
	if len(ts.roots) > 0 {
		req.RootCAsPEM = string(ts.roots)
	}
	if ts.opts.KillSwitch != nil {
		req.Tunnel = &daemonKnobs{KillSwitch: ts.opts.KillSwitch}
	}
	if req.DataToken == "" {
		return nil, ErrInvalidSession
	}
	rep, err := d.call(ctx, req, ts.opts.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	if !rep.OK {
		msg := rep.Error
		if msg == "" {
			msg = "connect refused"
		}
		return nil, tunnelUnavailable("%s", msg)
	}
	st := daemonStatus{}
	if rep.Status != nil {
		st = *rep.Status
	}
	var gw *GatewayDescriptor
	for i := range candidates {
		if candidates[i].ID == st.CandidateID {
			g := candidates[i]
			gw = &g
			break
		}
	}
	if gw == nil {
		_, _ = d.call(ctx, map[string]string{"op": "disconnect"}, 5*time.Second)
		return nil, tunnelUnavailable("connected candidate is not in the list")
	}
	if !isLoopbackHostPort(st.HTTPAddr) {
		// The daemon binds loopback only; a handle that says otherwise is not
		// the daemon this library drives, and nothing goes through it.
		_, _ = d.call(ctx, map[string]string{"op": "disconnect"}, 5*time.Second)
		return nil, tunnelUnavailable("the daemon's proxy is not on a loopback address")
	}
	base, err := dataBaseURL(gw, st.NodeTunnelIP)
	if err != nil {
		_, _ = d.call(ctx, map[string]string{"op": "disconnect"}, 5*time.Second)
		return nil, err
	}
	proxyURL := &url.URL{Scheme: "http", Host: st.HTTPAddr}
	tr := &http.Transport{
		// A fixed proxy, never the environment's: whether a payload rides
		// the tunnel is not HTTP_PROXY's or NO_PROXY's decision.
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	t := &target{base: base, client: &http.Client{Transport: tr, Timeout: ts.timeout}, tunnelled: true}

	ts.mu.Lock()
	ts.gateway = gw
	ts.last = st
	ts.tgt = t
	ts.mu.Unlock()
	return t, nil
}

// dataBaseURL is the payload surface's address: the node's tunnel address on
// the port its handshake listener used, plain HTTP — the tunnel is the
// transport security.
func dataBaseURL(gw *GatewayDescriptor, nodeIP string) (string, error) {
	if nodeIP == "" {
		return "", tunnelUnavailable("handshake returned no node tunnel address")
	}
	host, _, _ := strings.Cut(nodeIP, "/")
	port := "443"
	if u, err := url.Parse(gw.HandshakeEndpoint); err == nil && u.Port() != "" {
		port = u.Port()
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func (ts *tunnelState) dropTransport() {
	ts.mu.Lock()
	t := ts.tgt
	ts.tgt, ts.gateway, ts.last = nil, nil, daemonStatus{}
	ts.mu.Unlock()
	if t != nil {
		t.client.CloseIdleConnections()
	}
}

// isProxyFailure is true when the daemon's proxy, not the node, answered: the
// tunnel could not carry the request. The body is restored for the caller
// when it is not.
func isProxyFailure(resp *http.Response) bool {
	if resp.StatusCode != http.StatusBadGateway {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return bytes.Contains(b, []byte(proxyUnreachable))
}

// noteFailure follows a request the tunnel did not carry: it asks the
// daemon, and a tunnel the daemon has given up on is dropped so the next
// call re-selects. The daemon's own failover is left to run.
func (ts *tunnelState) noteFailure(ctx context.Context) {
	ts.mu.Lock()
	d := ts.daemon
	ts.mu.Unlock()
	if d == nil {
		return
	}
	st := daemonStatus{State: "down"}
	if d.alive() {
		if rep, err := d.call(ctx, map[string]string{"op": "status"}, 5*time.Second); err == nil && rep.Status != nil {
			st = *rep.Status
		}
	}
	if st.State == "" || st.State == "down" {
		ts.dropTransport()
		return
	}
	ts.mu.Lock()
	ts.last = st
	ts.mu.Unlock()
}

// renewLease follows a token rotation: the lease is presented with the new
// data_token now, and the daemon's answer is the caller's. No tunnel is
// nothing to renew, and no error.
func (ts *tunnelState) renewLease(ctx context.Context, dataToken string) error {
	ts.mu.Lock()
	d, t := ts.daemon, ts.tgt
	ts.mu.Unlock()
	if d == nil || t == nil || !d.alive() {
		return nil
	}
	rep, err := d.call(ctx, map[string]string{"op": "renew", "data_token": dataToken}, 30*time.Second)
	if err != nil {
		return err
	}
	if !rep.OK {
		msg := rep.Error
		if msg == "" {
			msg = "refused"
		}
		return tunnelUnavailable("lease renewal after token renewal: %s", msg)
	}
	if rep.Status != nil {
		ts.mu.Lock()
		ts.last = *rep.Status
		ts.mu.Unlock()
	}
	return nil
}

func (ts *tunnelState) refreshStatus(ctx context.Context) *TunnelStatus {
	ts.mu.Lock()
	d := ts.daemon
	ts.mu.Unlock()
	if d != nil {
		st := daemonStatus{State: "down"}
		if d.alive() {
			if rep, err := d.call(ctx, map[string]string{"op": "status"}, 5*time.Second); err == nil && rep.Status != nil {
				st = *rep.Status
			}
		}
		ts.mu.Lock()
		ts.last = st
		ts.mu.Unlock()
	}
	return ts.status()
}

func (ts *tunnelState) status() *TunnelStatus {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	st := ts.last
	out := &TunnelStatus{
		Mode:           ts.opts.Mode,
		State:          st.State,
		ClientTunnelIP: st.ClientTunnelIP,
		NodeTunnelIP:   st.NodeTunnelIP,
		AllowedIPs:     append([]string(nil), st.AllowedIPs...),
		LeaseExpiresAt: parseTime(st.LeaseExpiresAt),
		LastHandshake:  parseTime(st.LastHandshake),
		Reconnects:     st.Reconnects,
		LastError:      st.LastError,
	}
	if out.State == "" {
		out.State = "down"
	}
	if out.State != "down" && ts.gateway != nil {
		g := *ts.gateway
		out.Gateway = &g
	}
	if ts.daemon != nil {
		out.DaemonPID = ts.daemon.pid()
	}
	return out
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// close disconnects the tunnel and stops a daemon this client started. A
// daemon named by DaemonSocket stays running.
func (ts *tunnelState) close() error {
	ts.connectMu.Lock() // wait out an establishment in flight
	defer ts.connectMu.Unlock()
	ts.dropTransport()
	ts.mu.Lock()
	d := ts.daemon
	ts.daemon = nil
	ts.closed = true
	ts.mu.Unlock()
	if d == nil {
		return nil
	}
	if d.alive() {
		_, _ = d.call(context.Background(), map[string]string{"op": "disconnect"}, 5*time.Second)
	}
	if d.spawned() {
		d.stop()
	}
	return nil
}

// ============================================================================
// Gateway selection (a Control Plane call)
// ============================================================================

type gatewaySelectRequest struct {
	Country       string `json:"country,omitempty"`
	Region        string `json:"region,omitempty"`
	CUIMarking    string `json:"cui_marking,omitempty"`
	PoolID        string `json:"pool_id,omitempty"`
	MaxCandidates int    `json:"max_candidates,omitempty"`
}

type gatewaySelectResponse struct {
	Candidates   []GatewayDescriptor `json:"candidates"`
	TunnelPolicy *TunnelPolicy       `json:"tunnel_policy,omitempty"`
}

// selectGateways asks the Control Plane for the candidate list, re-applies
// the geofence, and reads the traffic policy in the daemon's shape.
func (c *Client) selectGateways(ctx context.Context) ([]GatewayDescriptor, *daemonPolicy, error) {
	t := c.opts.Tunnel
	body, err := json.Marshal(gatewaySelectRequest{
		Country:       t.Country,
		Region:        t.Region,
		CUIMarking:    string(t.CUIMarking),
		PoolID:        c.session.sovereignPool(),
		MaxCandidates: t.MaxCandidates,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("culperlink: marshal gateway selection: %w", err)
	}
	var resp gatewaySelectResponse
	if err := c.doRequest(ctx, http.MethodPost, "/sdk/v1/gateways/select", body, &resp); err != nil {
		if api, ok := errorsAsAPI(err); ok {
			switch {
			case api.Code == "GATEWAY_UNAVAILABLE":
				return nil, nil, fmt.Errorf("%w: %w", ErrSovereignNodeUnavailable, api)
			case api.StatusCode == http.StatusNotFound:
				return nil, nil, fmt.Errorf("%w: gateway selection is not served by this installation "+
					"(set Options.Tunnel.Mode = TunnelOff for an HTTPS-only installation): %w", ErrTunnelUnavailable, api)
			}
		}
		return nil, nil, fmt.Errorf("%w: gateway selection: %w", ErrTunnelUnavailable, err)
	}
	fence := geofenceFor(t.CUIMarking)
	kept := make([]GatewayDescriptor, 0, len(resp.Candidates))
	for _, d := range resp.Candidates {
		if d.Status == "offline" || fence.violation(d) != "" {
			continue
		}
		kept = append(kept, d)
	}
	if len(kept) == 0 {
		return nil, nil, fmt.Errorf("%w: the candidate list is empty after the geofence", ErrSovereignNodeUnavailable)
	}
	// The organisation's policy is on the envelope and nowhere else: it is
	// the organisation's, not a node's.
	return kept, policyForDaemon(resp.TunnelPolicy), nil
}

// policyForDaemon is the wire policy in the daemon's request shape; nil means
// the daemon's default, node_only. The daemon validates it.
func policyForDaemon(p *TunnelPolicy) *daemonPolicy {
	if p == nil {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "node_only"
	}
	return &daemonPolicy{
		Mode:             mode,
		Prefixes:         append([]string{}, p.Prefixes...),
		DNSThroughTunnel: strings.EqualFold(strings.TrimSpace(p.DNS.Mode), "tunnel"),
		Resolvers:        append([]string{}, p.DNS.Resolvers...),
		IPv6:             p.IPv6,
	}
}

// UnmarshalJSON accepts the agreed object and, leniently, a bare string for
// the mode, so "host" reads the same as {"mode":"host"}.
func (p *TunnelDNSPolicy) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*p = TunnelDNSPolicy{}
		return nil
	}
	if trimmed[0] == '"' {
		var mode string
		if err := json.Unmarshal(trimmed, &mode); err != nil {
			return err
		}
		*p = TunnelDNSPolicy{Mode: mode}
		return nil
	}
	type plain TunnelDNSPolicy
	var v plain
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return err
	}
	*p = TunnelDNSPolicy(v)
	return nil
}
