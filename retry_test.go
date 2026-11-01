package culperlink

// retry_test.go — the retry policy (retry.go; CulperLink CULPER-466, audit
// findings G-12 and G-21) and the rule that a request sent again is the same
// request (CULPER-331). The same tests, rule for rule, as CulperLink's own
// Go client's.
//
// The fake service counts the attempts that reach it and answers from a
// script; a listener in front of it can refuse connections before the TLS
// handshake completes. Waits go through pause, which the tests replace so
// they can count the waits without sleeping through them.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// receivedAttempt is one request as the fake saw it: the body it read to EOF
// and the length the request declared.
type receivedAttempt struct {
	method        string
	path          string
	body          []byte
	contentLength int64
}

// answer is one scripted reply. A zero status is "answer for real": 200 with
// a body every operation can decode.
type answer struct {
	status     int
	code       string // the service's error code; "" sends a plain-text body
	retryAfter string // the Retry-After header; "" sends none
	hold       time.Duration
}

// flakyService answers the API-key exchange, then answers every other
// request from its script, in order, and for real once the script is spent.
type flakyService struct {
	srv *httptest.Server

	mu       sync.Mutex
	attempts []receivedAttempt
	script   []answer
	auths    int
	// repeat, when set, is the answer for every request after the script.
	repeat *answer

	connMu   sync.Mutex
	newConns int
}

func newFlakyService(t *testing.T, script ...answer) *flakyService {
	t.Helper()
	f := &flakyService{script: script}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve(t)))
	f.srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			f.connMu.Lock()
			f.newConns++
			f.connMu.Unlock()
		}
	}
	f.srv.Start()
	t.Cleanup(f.srv.Close)
	return f
}

// always is a fake whose every answer after the exchange is a.
func always(t *testing.T, a answer) *flakyService {
	f := newFlakyService(t)
	f.repeat = &a
	return f
}

func (f *flakyService) serve(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/sdk/v1/auth/api-key" {
			f.mu.Lock()
			f.auths++
			f.mu.Unlock()
			writeTokenPair(w)
			return
		}

		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		f.mu.Lock()
		f.attempts = append(f.attempts, receivedAttempt{method: r.Method, path: r.URL.Path, body: got, contentLength: r.ContentLength})
		var a answer
		switch {
		case len(f.script) > 0:
			a, f.script = f.script[0], f.script[1:]
		case f.repeat != nil:
			a = *f.repeat
		}
		f.mu.Unlock()

		if a.hold > 0 {
			select {
			case <-time.After(a.hold):
			case <-r.Context().Done():
				return
			}
		}
		if a.status == 0 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ciphertext": "Y3Q=", "nonce": "bg==",
				"ephemeral_public_key": "ZQ==", "key_id": "kr_test.1", "aad": "",
				"plaintext": "cA==", "valid": true, "proof_hash": "abc", "cui_marking": "", "payload_version": 2,
			})
			return
		}
		if a.retryAfter != "" {
			w.Header().Set("Retry-After", a.retryAfter)
		}
		if a.code == "" {
			// Plain text, not the service's envelope: a bare 502 or 503 is
			// a gateway's answer, and inventing a service code for it is the
			// CULPER-333 defect (tests/sdk_fake_codes_test.go). A body, so
			// that a response closed without being drained would leave bytes
			// on the wire and cost the connection.
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(a.status)
			_, _ = w.Write([]byte(strings.Repeat("transient ", 64)))
			return
		}
		w.WriteHeader(a.status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{"code": a.code, "message": "scripted"},
		})
	}
}

func writeTokenPair(w http.ResponseWriter) {
	now := time.Now().UTC()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"session_token": "session-token",
		"data_token":    "data-token",
		"expires_at":    now.Add(time.Hour),
		"session": map[string]interface{}{
			"id": "sess-1", "tier": "enterprise",
			"issued_at": now, "expires_at": now.Add(time.Hour),
		},
	})
}

func (f *flakyService) client(t *testing.T, maxRetries int, mutate ...func(*Options)) *Client {
	t.Helper()
	opts := Options{APIKey: "clk_live_test", Endpoint: f.srv.URL, MaxRetries: Retries(maxRetries), Tunnel: TunnelOptions{Mode: TunnelOff}}
	for _, m := range mutate {
		m(&opts)
	}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (f *flakyService) received() []receivedAttempt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]receivedAttempt(nil), f.attempts...)
}

func (f *flakyService) authCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auths
}

func (f *flakyService) reset(script ...answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = nil
	f.script = script
}

func (f *flakyService) connections() int {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	return f.newConns
}

// countPauses replaces pause for one test: every wait is recorded and none
// is slept through. A context that is already done still ends the wait.
func countPauses(t *testing.T) func() []time.Duration {
	t.Helper()
	var mu sync.Mutex
	var waits []time.Duration
	prev := pause
	pause = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return ctx.Err()
	}
	t.Cleanup(func() { pause = prev })
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Duration(nil), waits...)
	}
}

func getVerify(c *Client) error {
	var out map[string]interface{}
	return c.doRequest(context.Background(), http.MethodGet, "/sdk/v1/verify?proof_hash=abc", nil, &out)
}

func postAttest(c *Client) error {
	var out map[string]interface{}
	return c.doControlRequestWithDataToken(context.Background(), http.MethodPost, "/sdk/v1/attest", []byte(`{"claim_subject":"s"}`), &out)
}

// Every attempt that is sent again carries the full original body, and
// declares its true length (CULPER-331). A POST is sent again only under
// rule 4 now, so the rate limiter's short Retry-After is what drives the
// second attempt. Both planes, and Encrypt, the call the ticket was filed
// against.
func TestResentRequestReplaysTheFullBody(t *testing.T) {
	countPauses(t)
	body := []byte(`{"payload":"` + strings.Repeat("Zm9vYmFy", 512) + `","channel":"conv-42"}`)
	limited := answer{status: http.StatusTooManyRequests, code: "RATE_LIMITED", retryAfter: "1"}

	cases := []struct {
		name string
		send func(c *Client) ([]byte, error)
	}{
		{"control plane POST", func(c *Client) ([]byte, error) {
			var out map[string]interface{}
			return body, c.doRequest(context.Background(), "POST", "/sdk/v1/gateways/select", body, &out)
		}},
		{"data plane POST", func(c *Client) ([]byte, error) {
			var out map[string]interface{}
			return body, c.doDataRequest(context.Background(), "POST", "/sdk/v1/decrypt", body, &out)
		}},
		{"Encrypt", func(c *Client) ([]byte, error) {
			_, err := c.Encrypt(context.Background(), bytes.Repeat([]byte("plaintext "), 300), "conv-42")
			return nil, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlakyService(t, limited)
			c := f.client(t, 2)
			want, err := tc.send(c)
			if err != nil {
				t.Fatalf("request should succeed after one Retry-After: %v", err)
			}
			got := f.received()
			if len(got) != 2 {
				t.Fatalf("attempts = %d, want 2", len(got))
			}
			if want == nil {
				// A public method serializes its own body; the first attempt
				// is the reference the second must match.
				want = got[0].body
			}
			if len(want) == 0 {
				t.Fatal("reference body is empty; the test is not exercising a body")
			}
			for i, a := range got {
				if !bytes.Equal(a.body, want) {
					t.Errorf("attempt %d body = %d bytes, want the original %d bytes", i+1, len(a.body), len(want))
				}
				if a.contentLength != int64(len(a.body)) {
					t.Errorf("attempt %d declared Content-Length %d, received %d bytes", i+1, a.contentLength, len(a.body))
				}
			}
		})
	}
}

// Repeated retry sequences reuse one connection. A response closed without
// being drained cannot go back to the pool, so a leak shows up as one new
// connection per failed attempt. GET, because a GET is what a 502 retries.
func TestRetryDoesNotLeakConnections(t *testing.T) {
	countPauses(t)
	const (
		rounds     = 3
		maxRetries = 2
	)
	bad := answer{status: http.StatusBadGateway}
	f := newFlakyService(t)
	c := f.client(t, maxRetries)

	for round := 0; round < rounds; round++ {
		f.reset(bad, bad)
		if err := getVerify(c); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if got := len(f.received()); got != maxRetries+1 {
			t.Fatalf("round %d: attempts = %d, want %d", round, got, maxRetries+1)
		}
	}
	// One for the API-key exchange and every request after it.
	if got := f.connections(); got != 1 {
		t.Fatalf("server saw %d connections across %d requests, want 1 (one per undrained response would be %d)",
			got, rounds*(maxRetries+1)+1, rounds*maxRetries+1)
	}
}

// The final response is drained too: a persistent failure that exhausts the
// budget still leaves the connection reusable.
func TestExhaustedRetryStillReturnsTheConnection(t *testing.T) {
	countPauses(t)
	f := always(t, answer{status: http.StatusGatewayTimeout})
	c := f.client(t, 1)
	for round := 0; round < 3; round++ {
		err := getVerify(c)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusGatewayTimeout {
			t.Fatalf("round %d: err = %v, want the gateway's 504", round, err)
		}
	}
	if got := f.connections(); got != 1 {
		t.Fatalf("server saw %d connections, want 1", got)
	}
}

// TestRetryPolicyTable pins rules 2 to 5 of retry.go, method by method:
// what is sent again, how often, and what is waited for. The service answers
// every attempt the same way, so the count is the client's decision alone.
func TestRetryPolicyTable(t *testing.T) {
	const maxRetries = 2
	cases := []struct {
		name         string
		method       string
		a            answer
		wantAttempts int
		wantWaits    []time.Duration // nil: the transient backoff, one per retry
	}{
		// Rule 2: a GET is sent again on a gateway's 502, 503 and 504.
		{"GET 502", "GET", answer{status: 502}, maxRetries + 1, nil},
		{"GET 503 with no service code", "GET", answer{status: 503}, maxRetries + 1, nil},
		{"GET 504", "GET", answer{status: 504}, maxRetries + 1, nil},
		{"GET 500", "GET", answer{status: 500, code: "INTERNAL_ERROR"}, 1, nil},
		// The service's own refusals are answers.
		{"GET 401", "GET", answer{status: 401, code: "UNAUTHORIZED"}, 1, nil},
		{"GET 403", "GET", answer{status: 403, code: "FORBIDDEN"}, 1, nil},
		{"GET 404", "GET", answer{status: 404, code: "NOT_FOUND"}, 1, nil},
		{"GET 422", "GET", answer{status: 422, code: "VALIDATION_ERROR"}, 1, nil},
		// Rule 5: a 503 with a service code is definitive, GET included.
		{"GET 503 GATEWAY_UNAVAILABLE", "GET", answer{status: 503, code: "GATEWAY_UNAVAILABLE"}, 1, nil},
		{"GET 503 VERIFICATION_KEY_UNAVAILABLE", "GET", answer{status: 503, code: "VERIFICATION_KEY_UNAVAILABLE"}, 1, nil},
		// Rule 3: a POST that was sent is never sent again.
		{"POST 500", "POST", answer{status: 500, code: "INTERNAL_ERROR"}, 1, nil},
		{"POST 502", "POST", answer{status: 502}, 1, nil},
		{"POST 503 with no service code", "POST", answer{status: 503}, 1, nil},
		{"POST 504", "POST", answer{status: 504}, 1, nil},
		{"POST 503 ATTESTATION_UNAVAILABLE", "POST", answer{status: 503, code: "ATTESTATION_UNAVAILABLE"}, 1, nil},
		{"POST 503 GATEWAY_UNAVAILABLE", "POST", answer{status: 503, code: "GATEWAY_UNAVAILABLE"}, 1, nil},
		{"POST 503 GATEWAY_SELECTION_NOT_CONFIGURED", "POST", answer{status: 503, code: "GATEWAY_SELECTION_NOT_CONFIGURED"}, 1, nil},
		// Rule 4: the limiter's Retry-After, once per call, any method.
		{"GET 429 Retry-After 1", "GET", answer{status: 429, code: "RATE_LIMITED", retryAfter: "1"}, 2, []time.Duration{time.Second}},
		{"POST 429 Retry-After 1", "POST", answer{status: 429, code: "RATE_LIMITED", retryAfter: "1"}, 2, []time.Duration{time.Second}},
		{"POST 429 Retry-After 10", "POST", answer{status: 429, code: "RATE_LIMITED", retryAfter: "10"}, 2, []time.Duration{10 * time.Second}},
		{"POST 429 Retry-After 11", "POST", answer{status: 429, code: "RATE_LIMITED", retryAfter: "11"}, 1, []time.Duration{}},
		{"GET 429 Retry-After 60", "GET", answer{status: 429, code: "RATE_LIMITED", retryAfter: "60"}, 1, []time.Duration{}},
		{"GET 429 without Retry-After", "GET", answer{status: 429, code: "RATE_LIMITED"}, 1, []time.Duration{}},
		{"GET 503 RATE_LIMIT_UNAVAILABLE", "GET", answer{status: 503, code: "RATE_LIMIT_UNAVAILABLE", retryAfter: "5"}, 2, []time.Duration{5 * time.Second}},
		{"POST 503 RATE_LIMIT_UNAVAILABLE", "POST", answer{status: 503, code: "RATE_LIMIT_UNAVAILABLE", retryAfter: "5"}, 2, []time.Duration{5 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			waits := countPauses(t)
			f := always(t, tc.a)
			c := f.client(t, maxRetries)
			var err error
			if tc.method == "GET" {
				err = getVerify(c)
			} else {
				err = postAttest(c)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.a.status {
				t.Fatalf("err = %v, want the service's %d", err, tc.a.status)
			}
			if got := len(f.received()); got != tc.wantAttempts {
				t.Fatalf("attempts = %d, want %d", got, tc.wantAttempts)
			}
			want := tc.wantWaits
			if want == nil {
				for i := 1; i < tc.wantAttempts; i++ {
					want = append(want, backoff(i-1))
				}
			}
			if got := waits(); (len(got) > 0 || len(want) > 0) && fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("waits = %v, want %v", got, want)
			}
		})
	}
}

// Rule 4's single resend: a second refusal is returned, with the wait it
// named, and it is the right sentinel for each of the two codes. The
// Retry-After header alone is enough; the body need not repeat it.
func TestRetryAfterIsCarriedOnTheError(t *testing.T) {
	countPauses(t)
	f := always(t, answer{status: 429, code: "RATE_LIMITED", retryAfter: "60"})
	err := getVerify(f.client(t, 1))
	var apiErr *APIError
	if !errors.Is(err, ErrRateLimited) || !errors.As(err, &apiErr) || apiErr.RetryAfter != 60 {
		t.Fatalf("err = %v (%+v), want ErrRateLimited with RetryAfter 60", err, apiErr)
	}
	if errors.Is(err, ErrRateLimitUnavailable) {
		t.Fatal("RATE_LIMITED matched ErrRateLimitUnavailable; the two are siblings")
	}

	f = always(t, answer{status: 503, code: "RATE_LIMIT_UNAVAILABLE", retryAfter: "5"})
	err = getVerify(f.client(t, 1))
	if !errors.Is(err, ErrRateLimitUnavailable) || !errors.As(err, &apiErr) || apiErr.RetryAfter != 5 {
		t.Fatalf("err = %v, want ErrRateLimitUnavailable with RetryAfter 5", err)
	}
	if errors.Is(err, ErrRateLimited) {
		t.Fatal("RATE_LIMIT_UNAVAILABLE matched ErrRateLimited; the caller is not over its limit")
	}
	if got := len(f.received()); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

// Rule 4's wait ends with the caller's context.
func TestRetryAfterWaitEndsWithTheContext(t *testing.T) {
	f := always(t, answer{status: 429, code: "RATE_LIMITED", retryAfter: "5"})
	c := f.client(t, 1)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	var out map[string]interface{}
	err := c.doRequest(ctx, http.MethodGet, "/sdk/v1/verify", nil, &out)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context's deadline", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the Retry-After wait outlived the caller's context")
	}
	if got := len(f.received()); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

// Rule 2 and rule 3 on a timeout: the service holds the answer past the
// client's Timeout. A GET is sent again; a POST is not, because the server
// may already have acted on it.
func TestTimeoutIsRetriedForGETOnly(t *testing.T) {
	countPauses(t)
	slow := answer{hold: 2 * time.Second}
	short := func(o *Options) { o.Timeout = 150 * time.Millisecond }

	f := always(t, slow)
	err := getVerify(f.client(t, 2, short))
	if err == nil || !isTimeout(err) {
		t.Fatalf("GET: err = %v, want a timeout", err)
	}
	if got := len(f.received()); got != 3 {
		t.Fatalf("GET attempts = %d, want 3", got)
	}

	f = always(t, slow)
	c := f.client(t, 2, short)
	_, err = c.Encrypt(context.Background(), []byte("held"), "ch")
	if err == nil || !isTimeout(err) {
		t.Fatalf("Encrypt: err = %v, want a timeout", err)
	}
	if got := len(f.received()); got != 1 {
		t.Fatalf("Encrypt attempts = %d, want 1: an encrypt the server may have answered is not sent again", got)
	}
}

// Rule 6: a refused session is returned on the first answer. The client
// does not present the API key again on its own.
func TestRefusedSessionIsNotReauthenticated(t *testing.T) {
	countPauses(t)
	f := always(t, answer{status: 401, code: "UNAUTHORIZED"})
	c := f.client(t, 3)
	err := getVerify(c)
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("err = %v, want ErrInvalidSession", err)
	}
	if got := len(f.received()); got != 1 {
		t.Fatalf("verify attempts = %d, want 1", got)
	}
	if got := f.authCount(); got != 1 {
		t.Fatalf("API-key exchanges = %d, want 1 (no automatic re-authentication)", got)
	}
}

// refusingListener resets the first n connections it accepts, before the
// TLS handshake: the client's request was never written.
type refusingListener struct {
	net.Listener
	refuse  atomic.Int32
	refused atomic.Int32
}

func (l *refusingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.refuse.Load() > 0 {
			l.refuse.Add(-1)
			l.refused.Add(1)
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// refusingService is flakyService over TLS behind a refusingListener, with
// keep-alives off so every request needs a connection of its own.
func refusingService(t *testing.T) (*flakyService, *refusingListener, []byte) {
	t.Helper()
	f := &flakyService{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve(t)))
	ln := &refusingListener{Listener: f.srv.Listener}
	f.srv.Listener = ln
	f.srv.Config.SetKeepAlivesEnabled(false)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return f, ln, caPEM
}

// Rule 1: a connection that failed before the request was written is sent
// again whatever the method — POST included, since the server never saw it.
func TestConnectionFailureBeforeSendingIsRetriedAnyMethod(t *testing.T) {
	countPauses(t)
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			f, ln, caPEM := refusingService(t)
			c := f.client(t, 1, func(o *Options) { o.TLS = TLSConfig{CACertPEM: caPEM} })
			if err := c.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			ln.refuse.Store(1)
			var err error
			if method == "GET" {
				err = getVerify(c)
			} else {
				err = postAttest(c)
			}
			if err != nil {
				t.Fatalf("%s after one refused connection: %v", method, err)
			}
			if got := ln.refused.Load(); got != 1 {
				t.Fatalf("refused connections = %d, want 1", got)
			}
			if got := len(f.received()); got != 1 {
				t.Fatalf("requests the server read = %d, want 1", got)
			}
		})
	}
	// With MaxRetries 0 nothing is sent again, not even a request the server
	// never saw.
	f, ln, caPEM := refusingService(t)
	c := f.client(t, 0, func(o *Options) { o.TLS = TLSConfig{CACertPEM: caPEM} })
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ln.refuse.Store(1)
	if err := postAttest(c); err == nil {
		t.Fatal("Retries(0): a refused connection was sent again")
	}
}

// Rule 3 for a transport failure: a POST whose connection broke after the
// request was written is not sent again.
func TestPOSTBrokenAfterSendingIsNotRetried(t *testing.T) {
	countPauses(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sdk/v1/auth/api-key" {
			writeTokenPair(w)
			return
		}
		hits.Add(1)
		_, _ = io.ReadAll(r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Options{APIKey: "k", Endpoint: srv.URL, MaxRetries: Retries(3), Tunnel: TunnelOptions{Mode: TunnelOff}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := postAttest(c); err == nil {
		t.Fatal("a connection closed without an answer was reported as success")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("attest attempts = %d, want 1", got)
	}
}

// The token exchange is a POST like any other: a refusal that was sent is
// not sent again (a second exchange would mint a second session).
func TestTokenExchangeIsNotResentAfterSending(t *testing.T) {
	countPauses(t)
	var auths atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Options{APIKey: "k", Endpoint: srv.URL, MaxRetries: Retries(3), Tunnel: TunnelOptions{Mode: TunnelOff}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Connect(context.Background()); err == nil {
		t.Fatal("a 502 from the token exchange was reported as success")
	}
	if got := auths.Load(); got != 1 {
		t.Fatalf("token exchanges = %d, want 1", got)
	}
}

// addressLike is a dotted address or a host:port in an error message.
var addressLike = regexp.MustCompile(`\d\.\d|:\d+`)

// TestMaxRetriesZeroTurnsOffEveryResend: Retries(0) is one attempt, the
// Retry-After resend included; nil keeps the default of 3.
func TestMaxRetriesZeroTurnsOffEveryResend(t *testing.T) {
	countPauses(t)
	tests := []struct {
		name         string
		maxRetries   *int
		a            answer
		wantAttempts int
	}{
		{"zero is no retries", Retries(0), answer{status: 502}, 1},
		{"one is one retry", Retries(1), answer{status: 502}, 2},
		{"nil is the default", nil, answer{status: 502}, defaultMaxRetries + 1},
		{"zero waits out no Retry-After", Retries(0), answer{status: 429, code: "RATE_LIMITED", retryAfter: "1"}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := always(t, tc.a)
			c, err := NewClient(Options{APIKey: "clk_live_test", Endpoint: f.srv.URL, MaxRetries: tc.maxRetries, Tunnel: TunnelOptions{Mode: TunnelOff}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = getVerify(c)
			if got := len(f.received()); got != tc.wantAttempts {
				t.Fatalf("attempts = %d, want %d", got, tc.wantAttempts)
			}
		})
	}
	if _, err := NewClient(Options{APIKey: "k", Endpoint: "https://x.example", MaxRetries: Retries(-1)}); err == nil {
		t.Fatal("a negative MaxRetries was accepted")
	}
}
