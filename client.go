package culperlink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Version is this library's release version. Its tag in this repository is
// v<Version>, the same as the CulperLink release it was published with.
const Version = "0.2.0"

// dataTokenHeader carries the Data Plane credential. It is a different header
// from Authorization on purpose: a request that reaches the wrong plane fails
// to authenticate rather than quietly succeeding.
const dataTokenHeader = "X-Culper-Data-Token"

// Client is the entry point. A Client is safe for concurrent use and should
// be reused for the life of the process.
type Client struct {
	opts Options

	httpClient *http.Client // the Control Plane's
	session    *sessionState
	tunnel     *tunnelState // nil in TunnelOff
	maxRetries int          // Options.MaxRetries resolved: the default applied

	mu     sync.RWMutex
	closed bool
}

// Options configures a Client. APIKey and Endpoint are required.
type Options struct {
	// APIKey is the API key your installation issued. Required.
	APIKey string

	// Endpoint is the base URL of your CulperLink installation's Control
	// Plane. Required; there is no default.
	Endpoint string

	// Timeout is the per-request timeout. Defaults to 30s.
	Timeout time.Duration

	// MaxRetries bounds how many times a request the server cannot have
	// acted on is sent again: a connection that failed before the request
	// was written, or a GET that met a gateway error or a timeout. A POST
	// that was sent is never sent again. Nil means the default, 3.
	// Retries(0) turns off every resend, the rate limiter's Retry-After
	// included: an int field could not tell "unset" from 0, so 0 used to
	// mean 3 (CULPER-460 G-30). See retry.go.
	MaxRetries *int

	// UserAgent defaults to "culperlink-go/<Version>".
	UserAgent string

	// TLS configures how the installation's certificate is verified: a
	// private CA bundle, SPKI pinning and the TLS version floor. The zero
	// value is the system trust store with a TLS 1.3 floor. Ignored when
	// HTTPClient is set. Its CA bundle also anchors the node's handshake
	// listener unless Tunnel.RootCAsPEM is set.
	TLS TLSConfig

	// HTTPClient, if set, carries Control Plane calls (and, in TunnelOff,
	// Data Plane calls too). Prefer TLS for trust configuration.
	HTTPClient *http.Client

	// Tunnel configures the Data Plane transport. The zero value is
	// TunnelNetstack through a culperlink-tunnel daemon found on PATH.
	Tunnel TunnelOptions
}

// NewClient validates opts and applies defaults. It performs no network I/O
// and starts no daemon; the first operation, or Connect, does.
func NewClient(opts Options) (*Client, error) {
	if opts.APIKey == "" {
		return nil, ErrMissingAPIKey
	}
	if opts.Endpoint == "" {
		return nil, ErrMissingEndpoint
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	maxRetries := defaultMaxRetries
	if opts.MaxRetries != nil {
		if *opts.MaxRetries < 0 {
			return nil, errNegativeRetries
		}
		maxRetries = *opts.MaxRetries
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "culperlink-go/" + Version
	}
	switch opts.Tunnel.Mode {
	case "":
		opts.Tunnel.Mode = TunnelNetstack
	case TunnelNetstack, TunnelSystem, TunnelOff:
	default:
		return nil, ErrInvalidTunnelMode
	}

	c := &Client{opts: opts, session: newSessionState(), maxRetries: maxRetries}

	hc := opts.HTTPClient
	if hc == nil {
		if opts.TLS.isZero() {
			hc = &http.Client{Timeout: opts.Timeout}
		} else {
			var err error
			if hc, err = opts.TLS.httpClient(opts.Timeout); err != nil {
				return nil, err
			}
		}
	}
	c.httpClient = hc

	if opts.Tunnel.Mode != TunnelOff {
		roots := opts.Tunnel.RootCAsPEM
		if len(roots) == 0 {
			var err error
			if roots, err = opts.TLS.caPEM(); err != nil {
				return nil, err
			}
		}
		c.tunnel = newTunnelState(opts.Tunnel, roots, opts.Timeout)
	}
	return c, nil
}

// Connect authenticates and, unless Tunnel.Mode is TunnelOff, finds or starts
// the daemon, selects a node and brings the tunnel up. Optional: the first
// Encrypt or Decrypt does the same. Calling it at startup surfaces a bad API
// key, a missing daemon (ErrTunnelDaemonNotFound), no compliant node
// (ErrSovereignNodeUnavailable) or a refused handshake (ErrTunnelUnavailable)
// before the first payload.
func (c *Client) Connect(ctx context.Context) error {
	if c.IsClosed() {
		return ErrClientClosed
	}
	if err := c.session.ensureAuthenticated(ctx, c); err != nil {
		return err
	}
	if c.tunnel == nil {
		return nil
	}
	_, err := c.tunnel.ensure(ctx, c)
	return err
}

// Close disconnects the tunnel, stops a daemon this client started, and
// drops the session. Later calls return ErrClientClosed. Safe to call more
// than once. The tunnel's lease lapses on the node at its TTL.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	var err error
	if c.tunnel != nil {
		err = c.tunnel.close()
	}
	c.session.clear()
	return err
}

// Endpoint returns the configured Control Plane URL.
func (c *Client) Endpoint() string { return c.opts.Endpoint }

// IsClosed reports whether Close has been called.
func (c *Client) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// plane says which credential a request carries and where it is addressed.
// Those are two properties, not one: attest carries the data credential to
// the Control Plane's address (CULPER-419).
type plane int

const (
	controlPlane       plane = iota // session_token, to Options.Endpoint
	dataPlane                       // data_token, through the tunnel
	controlOnDataToken              // data_token, to Options.Endpoint: attest only
)

func (p plane) carriesDataToken() bool { return p == dataPlane || p == controlOnDataToken }

// doRequest issues a Control Plane request on session_token.
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte, out any) error {
	return c.send(ctx, controlPlane, method, path, body, out)
}

// doDataRequest issues a Data Plane request: data_token and NO
// Authorization header, through the tunnel unless the mode is TunnelOff.
func (c *Client) doDataRequest(ctx context.Context, method, path string, body []byte, out any) error {
	return c.send(ctx, dataPlane, method, path, body, out)
}

// doControlRequestWithDataToken carries data_token to Options.Endpoint.
// Attest is the only such operation; it is a separate name so that a call
// site says both halves.
func (c *Client) doControlRequestWithDataToken(ctx context.Context, method, path string, body []byte, out any) error {
	return c.send(ctx, controlOnDataToken, method, path, body, out)
}

// target is one attempt's destination and the client that carries it.
type target struct {
	base   string
	client *http.Client
	// tunnelled is true when the attempt goes through the daemon's proxy, so
	// a failure is reported to the daemon and a proxy 502 is recognised.
	tunnelled bool
}

// send is the one request path every plane goes through, under the retry
// policy in retry.go.
func (c *Client) send(ctx context.Context, p plane, method, path string, body []byte, out any) error {
	if c.IsClosed() {
		return ErrClientClosed
	}
	if err := c.session.ensureAuthenticated(ctx, c); err != nil {
		return err
	}

	tunnelled := p == dataPlane && c.tunnel != nil
	proxyFailed := false
	resp, err := c.roundTrip(ctx, method, func(actx context.Context, track func(*http.Request) *http.Request) (*http.Response, error) {
		proxyFailed = false
		tgt := target{base: c.opts.Endpoint, client: c.httpClient}
		if tunnelled {
			// Decided per attempt: a tunnel the daemon gave up on between
			// attempts is re-selected and re-established here.
			t, err := c.tunnel.ensure(actx, c)
			if err != nil {
				return nil, stopError{err}
			}
			tgt = t
		}
		req, err := newRequest(actx, c, method, tgt.base+path, body)
		if err != nil {
			return nil, stopError{err}
		}
		if err := c.setCredential(req, p); err != nil {
			return nil, stopError{err}
		}
		resp, err := tgt.client.Do(track(req))
		if tgt.tunnelled && (err != nil || isProxyFailure(resp)) {
			// The proxy, not the node, answered, or nothing did: ask the
			// daemon, and drop a tunnel it has given up on so the next
			// attempt or call re-establishes it.
			proxyFailed = err == nil
			c.tunnel.noteFailure(ctx)
		}
		return resp, err
	})
	if err != nil {
		var tErr *tunnelError
		if errors.As(err, &tErr) || errors.Is(err, ErrSovereignNodeUnavailable) || errors.Is(err, ErrSelectionNotConfigured) {
			return err
		}
		if tunnelled && isTimeout(err) {
			// A sent request that timed out is a timeout, not a tunnel
			// failure: the node may have acted on it (retry.go, rule 3).
			// The text names no address; the cause keeps Timeout().
			return &timeoutError{cause: err}
		}
		if tunnelled {
			// The transport's text names the node's tunnel address and the
			// proxy's port; the caller gets the class (G-26).
			return &tunnelError{msg: "culperlink: tunnel unavailable: the tunnel could not carry the request (" + transportClass(err) + ")", cause: err}
		}
		return fmt.Errorf("culperlink: request failed: %w", err)
	}
	defer drainAndClose(resp)
	if proxyFailed {
		return tunnelUnavailable("the tunnel could not carry the request")
	}
	return decodeResponse(resp, out)
}

// setCredential attaches the plane's credential, and only that one.
func (c *Client) setCredential(req *http.Request, p plane) error {
	if p.carriesDataToken() {
		tok := c.session.dataTokenValue()
		if tok == "" {
			// No fallback to the session token: that would send the
			// Control Plane credential across the boundary.
			return ErrInvalidSession
		}
		req.Header.Set(dataTokenHeader, tok)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+c.session.token())
	return nil
}

// newRequest builds one attempt from a body that is already buffered: a
// fresh reader per attempt, ContentLength and GetBody set from the buffer, so
// neither a retry nor the transport's own replay sends an empty body
// (CULPER-331). A nil body is a request without one.
func newRequest(ctx context.Context, c *Client, method, url string, body []byte) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, fmt.Errorf("culperlink: build request: %w", err)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// drainAndClose reads a body to EOF and closes it; a body closed with bytes
// unread costs its connection.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// backoff is the wait before the n-th transient retry: 100ms, 200ms, 400ms, ...
func backoff(attempt int) time.Duration {
	return time.Duration(100*(1<<attempt)) * time.Millisecond
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// errClass is the innermost cause of a local failure: the daemon's control
// socket, its executable, its directory. The innermost error ("connection
// refused", "no such file or directory") names no path and no address. A
// request's failure is classed by transportClass instead.
func errClass(err error) string {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return err.Error()
		}
		err = inner
	}
}

// defaultMaxRetries is the retry count when Options.MaxRetries is nil.
const defaultMaxRetries = 3

var errNegativeRetries = errors.New("culperlink: Options.MaxRetries must not be negative")

// Retries returns a pointer to n, for Options.MaxRetries: Retries(0) turns
// retries off, and leaving the field nil keeps the default of 3.
func Retries(n int) *int { return &n }

// redactedAPIKey stands in for the API key wherever an Options or a Client is
// printed (CULPER-460 G-11). Logging the options or the client is routine in
// error handlers and debug output, and fmt's %v, %+v and %#v print every
// field, so without these methods a routine debug line carried the
// long-lived credential in full.
const redactedAPIKey = "[REDACTED]"

// optionsNoMethods is Options without its methods, so formatting it does not
// recurse into String.
type optionsNoMethods Options

func (o Options) redacted() optionsNoMethods {
	if o.APIKey != "" {
		o.APIKey = redactedAPIKey
	}
	return optionsNoMethods(o)
}

// String formats the options with the API key redacted. It also serves %v
// and %+v.
func (o Options) String() string { return fmt.Sprintf("%+v", o.redacted()) }

// GoString formats the options for %#v with the API key redacted.
func (o Options) GoString() string {
	return strings.Replace(fmt.Sprintf("%#v", o.redacted()), "optionsNoMethods{", "Options{", 1)
}

// String names the client by its endpoint and nothing else: the session's
// tokens and the API key it holds are never printed.
func (c *Client) String() string {
	if c == nil {
		return "culperlink.Client(nil)"
	}
	return fmt.Sprintf("culperlink.Client{Endpoint: %q}", c.opts.Endpoint)
}

// GoString is String, for %#v.
func (c *Client) GoString() string { return c.String() }
