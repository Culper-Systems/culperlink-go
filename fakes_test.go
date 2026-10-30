package culperlink

// fakes_test.go — the stubs the unit tests run against, as the TypeScript
// library's specs do: an HTTPS Control Plane (httptest), and a fake
// culperlink-tunnel daemon that speaks the real control protocol over a real
// Unix socket and whose "proxy" plays the node. The fake daemon runs either
// in-process (DaemonSocket tests) or as this test binary re-executed
// (TestMain, for the spawn and exit-with-parent tests).
//
// No cryptography is under test here: the stub node "encrypts" by echoing,
// and binds the channel by carrying it in ephemeral_public_key, so that a
// wrong channel is a DECRYPTION_FAILED refusal as on the real service.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAPIKey    = "clk_test_key"
	nodeTunnelIP  = "10.200.0.1/32"
	nodeDataHost  = "10.200.0.1:8443"
	fakeNodeID    = "node-1"
	envFakeDaemon = "CULPERLINK_FAKE_DAEMON"
	envFakeRecord = "CULPERLINK_FAKE_DAEMON_RECORD"
	envFakeVer    = "CULPERLINK_FAKE_DAEMON_VERSION"
)

func TestMain(m *testing.M) {
	if os.Getenv(envFakeDaemon) == "1" {
		os.Exit(runFakeDaemonProcess(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// The stub node: the payload surface, served wherever the tests put it.
// ---------------------------------------------------------------------------

type violations struct {
	mu   sync.Mutex
	list []string
}

func (v *violations) add(format string, args ...any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.list = append(v.list, fmt.Sprintf(format, args...))
}

func (v *violations) get() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.list...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

// servePayload answers encrypt and decrypt on the data credential alone.
func servePayload(w http.ResponseWriter, r *http.Request, v *violations, validToken func(string) bool) bool {
	switch r.URL.Path {
	case "/sdk/v1/encrypt", "/sdk/v1/decrypt":
	default:
		return false
	}
	if r.Header.Get("Authorization") != "" {
		v.add("%s carried Authorization", r.URL.Path)
	}
	if !validToken(r.Header.Get(dataTokenHeader)) {
		apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "bad data token")
		return true
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	if r.URL.Path == "/sdk/v1/encrypt" {
		writeJSON(w, http.StatusOK, map[string]string{
			"ciphertext":           body["payload"],
			"nonce":                base64.StdEncoding.EncodeToString([]byte("nonce-12byte")),
			"ephemeral_public_key": base64.StdEncoding.EncodeToString([]byte(body["channel"])),
			"key_id":               "epoch-1",
		})
		return true
	}
	bound, _ := base64.StdEncoding.DecodeString(body["ephemeral_public_key"])
	if string(bound) != body["channel"] {
		apiErr(w, http.StatusBadRequest, "DECRYPTION_FAILED", "payload did not authenticate")
		return true
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": body["ciphertext"]})
	return true
}

// ---------------------------------------------------------------------------
// The stub Control Plane.
// ---------------------------------------------------------------------------

type fakeCP struct {
	srv *httptest.Server
	v   violations

	mu         sync.Mutex
	n          int
	sessions   map[string]bool
	data       map[string]bool
	hits       map[string]int
	selectBody []map[string]any
	ttl        time.Duration
	capAt      time.Time // when set, every pair expires here: the service's 12-hour clamp
	candidates []map[string]any
	policy     map[string]any
	// override, when set, answers first; returning true means handled.
	override func(w http.ResponseWriter, r *http.Request) bool
}

func newFakeCP(t *testing.T) *fakeCP {
	t.Helper()
	cp := &fakeCP{
		sessions: map[string]bool{}, data: map[string]bool{}, hits: map[string]int{},
		ttl:        time.Hour,
		candidates: []map[string]any{candidate(fakeNodeID, "US", "us-east-1")},
	}
	cp.srv = httptest.NewTLSServer(http.HandlerFunc(cp.serve))
	t.Cleanup(cp.srv.Close)
	return cp
}

func candidate(id, country, region string) map[string]any {
	return map[string]any{
		"id": id, "country": country, "region": region, "status": "online",
		"handshake_endpoint":   "https://node.example:8443",
		"wireguard_endpoint":   "node.example:51820",
		"wireguard_public_key": "d2lyZWd1YXJkLXB1YmxpYy1rZXktMzItYnl0ZXMhIQ==",
		"spki_pin":             "c3BraS1waW4tMzItYnl0ZXMtLS0tLS0tLS0tLS0tLS0=",
	}
}

func (cp *fakeCP) setOverride(f func(w http.ResponseWriter, r *http.Request) bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.override = f
}

func (cp *fakeCP) hit(path string) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.hits[path]
}

func (cp *fakeCP) caPEMFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pemEncode(cp.srv.Certificate().Raw)
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (cp *fakeCP) issue(w http.ResponseWriter) {
	cp.mu.Lock()
	cp.n++
	st, dt := fmt.Sprintf("st-%d", cp.n), fmt.Sprintf("dt-%d", cp.n)
	cp.sessions[st], cp.data[dt] = true, true
	exp := time.Now().Add(cp.ttl).UTC()
	if !cp.capAt.IsZero() {
		exp = cp.capAt
	}
	cp.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"session":       map[string]any{"id": "sess-1", "tier": TierEnterprise, "issued_at": time.Now().UTC(), "expires_at": exp},
		"session_token": st, "data_token": dt, "expires_at": exp,
	})
}

func (cp *fakeCP) bearer(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return ok && cp.sessions[tok]
}

func (cp *fakeCP) validData(tok string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.data[tok]
}

func (cp *fakeCP) serve(w http.ResponseWriter, r *http.Request) {
	cp.mu.Lock()
	cp.hits[r.URL.Path]++
	override := cp.override
	cp.mu.Unlock()
	if override != nil && override(w, r) {
		return
	}
	switch r.URL.Path {
	case "/sdk/v1/auth/api-key":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["api_key"] != testAPIKey {
			apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid api key")
			return
		}
		cp.issue(w)
		return
	case "/sdk/v1/auth/renew":
		if r.Header.Get(dataTokenHeader) != "" {
			cp.v.add("renew carried the data token")
		}
		if !cp.bearer(r) {
			apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid session")
			return
		}
		cp.issue(w)
		return
	}
	if servePayload(w, r, &cp.v, cp.validData) {
		return
	}
	switch r.URL.Path {
	case "/sdk/v1/attest":
		if r.Header.Get("Authorization") != "" {
			cp.v.add("attest carried Authorization")
		}
		if !cp.validData(r.Header.Get(dataTokenHeader)) {
			apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "bad data token")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"proof_hash": "proof-abc", "issued_at": time.Now().UTC(), "audit_log_url": "https://audit.example/proof-abc", "claim_subject": "doc"})
	case "/sdk/v1/verify", "/audit/v1/access", "/sdk/v1/gateways/select":
		if r.Header.Get(dataTokenHeader) != "" {
			cp.v.add("%s carried the data token", r.URL.Path)
		}
		if !cp.bearer(r) {
			apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid session")
			return
		}
		switch r.URL.Path {
		case "/sdk/v1/verify":
			writeJSON(w, http.StatusOK, map[string]bool{"valid": r.URL.Query().Get("proof_hash") == "proof-abc"})
		case "/audit/v1/access":
			writeJSON(w, http.StatusOK, []AuditLogEntry{{Date: "2026-10-27", Endpoint: "/sdk/v1/encrypt", Count: 2, HTTPStatus: "2xx"}})
		default:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			cp.mu.Lock()
			cp.selectBody = append(cp.selectBody, body)
			resp := map[string]any{"candidates": cp.candidates}
			if cp.policy != nil {
				resp["tunnel_policy"] = cp.policy
			}
			cp.mu.Unlock()
			writeJSON(w, http.StatusOK, resp)
		}
	default:
		apiErr(w, http.StatusNotFound, "NOT_FOUND", "no such route")
	}
}

// ---------------------------------------------------------------------------
// The fake daemon: the real control protocol over a real Unix socket.
// ---------------------------------------------------------------------------

type fakeDaemon struct {
	socket  string
	version any
	// proxy is the loopback "HTTP proxy": it plays the node for absolute
	// URLs to nodeDataHost, as the real daemon forwards them through the
	// tunnel.
	proxy *httptest.Server
	v     violations

	mu          sync.Mutex
	ops         []string
	tokens      []string
	connected   bool
	down        bool   // the proxy answers 502 as the real one does with no tunnel
	connectErr  string // non-empty: connect fails with it
	renewErr    string
	httpAddr    string // reported http_addr; defaults to the proxy's
	connectReqs []map[string]any
}

func newFakeDaemon(t *testing.T, version any) *fakeDaemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "clgo-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := &fakeDaemon{socket: filepath.Join(dir, "c.sock"), version: version}
	ln, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	d.startProxy()
	t.Cleanup(d.proxy.Close)
	go d.serve(ln)
	return d
}

func (d *fakeDaemon) startProxy() {
	d.proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "this is a proxy; use CONNECT or an absolute URL", http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		down, connected := d.down, d.connected
		d.mu.Unlock()
		if down || !connected || r.URL.Host != nodeDataHost {
			http.Error(w, proxyUnreachable, http.StatusBadGateway)
			return
		}
		if !servePayload(w, r, &d.v, func(tok string) bool { return d.tokenSeen(tok) }) {
			http.NotFound(w, r)
		}
	}))
}

func (d *fakeDaemon) tokenSeen(tok string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return tok != "" && len(d.tokens) > 0 && d.tokens[len(d.tokens)-1] == tok
}

func (d *fakeDaemon) opList() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.ops...)
}

func (d *fakeDaemon) set(f func(d *fakeDaemon)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d)
}

func (d *fakeDaemon) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go d.handle(c)
	}
}

func (d *fakeDaemon) status() map[string]any {
	state := "down"
	if d.connected {
		state = "up"
	}
	addr := d.httpAddr
	if addr == "" {
		addr = d.proxy.Listener.Addr().String()
	}
	st := map[string]any{"state": state, "mode": "netstack", "http_addr": addr, "socks_addr": "127.0.0.1:1"}
	if d.connected {
		st["candidate_id"] = fakeNodeID
		st["node_tunnel_ip"] = nodeTunnelIP
		st["client_tunnel_ip"] = "10.200.0.2/32"
		st["allowed_ips"] = []string{"10.200.0.1/32"}
		st["last_handshake"] = time.Now().UTC().Format(time.RFC3339)
		st["lease_expires_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	}
	return st
}

func (d *fakeDaemon) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return
	}
	var req map[string]any
	rep := map[string]any{}
	if json.Unmarshal(line, &req) != nil {
		rep["error"] = "malformed request"
	} else {
		d.mu.Lock()
		op, _ := req["op"].(string)
		d.ops = append(d.ops, op)
		switch op {
		case "status":
			rep["ok"] = true
		case "connect":
			d.connectReqs = append(d.connectReqs, req)
			tok, _ := req["data_token"].(string)
			if d.connectErr != "" {
				rep["error"] = d.connectErr
			} else {
				d.tokens = append(d.tokens, tok)
				d.connected, d.down = true, false
				rep["ok"] = true
			}
		case "renew":
			tok, _ := req["data_token"].(string)
			if d.renewErr != "" {
				rep["error"] = "renew: " + d.renewErr
			} else {
				d.tokens = append(d.tokens, tok)
				rep["ok"] = true
			}
		case "disconnect":
			d.connected = false
			rep["ok"] = true
		default:
			rep["error"] = "unknown op: " + op
		}
		rep["status"] = d.status()
		d.mu.Unlock()
	}
	rep["version"] = d.version
	b, _ := json.Marshal(rep)
	_, _ = c.Write(append(b, '\n'))
}

// runFakeDaemonProcess is the fake daemon as a process, parsing the flags
// the client passes the real one. It records its arguments, and exits on
// stdin EOF under -exit-with-parent, as the real daemon does.
func runFakeDaemonProcess(args []string) int {
	fs := flag.NewFlagSet(DaemonName, flag.ContinueOnError)
	socket := fs.String("socket", "", "")
	_ = fs.String("socks", "", "")
	_ = fs.String("http", "", "")
	_ = fs.String("log-level", "", "")
	exitWithParent := fs.Bool("exit-with-parent", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rec := os.Getenv(envFakeRecord); rec != "" {
		st, _ := os.Stat(filepath.Dir(*socket))
		mode := ""
		if st != nil {
			mode = fmt.Sprintf("%o", st.Mode().Perm())
		}
		_ = os.WriteFile(rec, []byte(strings.Join(args, " ")+"\ndirmode="+mode+"\n"), 0o600)
	}
	version := os.Getenv(envFakeVer)
	if version == "" {
		version = "0.2.0"
	}
	d := &fakeDaemon{socket: *socket, version: version}
	d.startProxy()
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		return 1
	}
	go d.serve(ln)
	if *exitWithParent {
		_, _ = io.Copy(io.Discard, os.Stdin)
		return 0
	}
	select {}
}

func pemEncode(der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(b64) > 64 {
		sb.WriteString(b64[:64] + "\n")
		b64 = b64[64:]
	}
	sb.WriteString(b64 + "\n-----END CERTIFICATE-----\n")
	return []byte(sb.String())
}
