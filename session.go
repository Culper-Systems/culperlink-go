package culperlink

// session.go — the client's authentication state: a PAIR of independent
// opaque tokens, session_token for the Control Plane and data_token for the
// Data Plane. They are kept in separate fields and handed out through
// separate accessors, they rotate together and are cleared together, and
// neither is ever sent where the other belongs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type sessionState struct {
	mu sync.RWMutex

	appToken  string // session_token: Control Plane calls
	dataToken string // data_token: Data Plane calls

	// byPasskey is set when the pair came from a passkey sign-in
	// (CULPER-469). Such a session is renewed and never replaced by an
	// API-key exchange, and stays set after the session ends so a later call
	// fails rather than signing in as the organisation; see auth.go.
	byPasskey bool

	current         *Session
	sovereignPoolID string

	refreshBeforeExpiry time.Duration

	// renewalCapped is set when a renewal returned an expiry no later than
	// the pair it replaced (CULPER-460 G-5). The service clamps renewal to
	// the session's 12-hour cap, so from five minutes before the cap every
	// renewal answers the same expiry, still inside refreshBeforeExpiry.
	// Without this every call renewed until the cap passed, and the
	// per-address limit the renew and API-key routes share turned that into
	// refusals. Once set, the pair is used until cappedMargin before it
	// expires, and then the API key is presented once for a new session.
	renewalCapped bool
	cappedMargin  time.Duration

	// refreshMu serialises renew/authenticate, so one renewal does not
	// become a herd of API-key exchanges (renewal is single-winner on the
	// service).
	refreshMu sync.Mutex
}

func newSessionState() *sessionState {
	return &sessionState{refreshBeforeExpiry: 5 * time.Minute, cappedMargin: 30 * time.Second}
}

// fresh reports whether both halves are present and good for long enough.
func (s *sessionState) fresh() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	buffer := s.refreshBeforeExpiry
	if s.renewalCapped {
		buffer = s.cappedMargin
	}
	return s.appToken != "" && s.dataToken != "" && s.current != nil &&
		time.Until(s.current.ExpiresAt) > buffer
}

// ensureAuthenticated guarantees a usable pair, renewing near expiry (which
// presents session_token, never the API key) and falling back to the API-key
// exchange when renewal fails for any reason — except for a passkey-issued
// session, which is a person's and is never replaced by the organisation's
// API key (auth.go).
func (s *sessionState) ensureAuthenticated(ctx context.Context, c *Client) error {
	if s.fresh() {
		return nil
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if s.fresh() {
		return nil
	}
	byPasskey := s.passkey()
	// A capped session cannot be extended: renewing again would only return
	// the same expiry, so go straight to the API key.
	if s.canRenew() && !s.capped() {
		err := s.renew(ctx, c)
		if err == nil {
			return c.afterTokenRotation(ctx)
		}
		if byPasskey {
			var api *APIError
			if !errors.As(err, &api) && !errors.Is(err, ErrInvalidSession) {
				// A transport failure says nothing about the session: keep
				// it, and let the caller see what happened.
				return err
			}
			// No API-key fallback for a person's session, and no loop: the
			// session is over, and the person signs in again.
			s.dropPair()
			return fmt.Errorf("%w: the passkey session could not be renewed; sign in again with a passkey: %w", ErrInvalidSession, err)
		}
	}
	if byPasskey {
		// At the lifetime cap, or already ended: a passkey session cannot be
		// re-issued without the person.
		s.dropPair()
		return fmt.Errorf("%w: the passkey session has ended; sign in again with a passkey", ErrInvalidSession)
	}
	if c.opts.APIKey == "" {
		return errNotSignedIn
	}
	if err := s.authenticate(ctx, c); err != nil {
		return err
	}
	return c.afterTokenRotation(ctx)
}

// errNotSignedIn is a call made with no API key and before any passkey
// sign-in. It matches ErrMissingAPIKey and names both ways in.
var errNotSignedIn = fmt.Errorf("%w: not signed in: set Options.APIKey, or sign in with a passkey (BeginPasskeyLogin, then FinishPasskeyLogin)", ErrMissingAPIKey)

// signInWithPasskey posts a finish-login body and installs the pair it
// returns, serialised with renewal and the API-key exchange so a sign-in
// never interleaves with another token install.
func (s *sessionState) signInWithPasskey(ctx context.Context, c *Client, body []byte) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if err := s.exchange(ctx, c, "/sdk/v1/auth/passkey/finish-login", body, ""); err != nil {
		return err
	}
	s.mu.Lock()
	s.byPasskey = true
	s.renewalCapped = false
	s.mu.Unlock()
	return c.afterTokenRotation(ctx)
}

func (s *sessionState) passkey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byPasskey
}

// dropPair forgets an ended passkey session's pair; byPasskey stays set, so
// the client remains the person's until the next sign-in. RotateSession is
// the explicit way back to the API key.
func (s *sessionState) dropPair() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appToken, s.dataToken = "", ""
	s.current = nil
	s.renewalCapped = false
}

// afterTokenRotation renews the tunnel's lease with the new data_token in the
// call chain that installed it, so a token the Control Plane is retiring is
// never the one carrying the lease. The daemon's refusal is the caller's
// error.
func (c *Client) afterTokenRotation(ctx context.Context) error {
	if c.tunnel == nil {
		return nil
	}
	return c.tunnel.renewLease(ctx, c.session.dataTokenValue())
}

func (s *sessionState) canRenew() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.appToken != ""
}

func (s *sessionState) capped() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.renewalCapped
}

func (s *sessionState) authenticate(ctx context.Context, c *Client) error {
	// #nosec G117 -- the API key is the intended body of the auth request
	body, err := json.Marshal(apiKeyAuthRequest{APIKey: c.opts.APIKey})
	if err != nil {
		return fmt.Errorf("culperlink: marshal api-key auth: %w", err)
	}
	if err := s.exchange(ctx, c, "/sdk/v1/auth/api-key", body, ""); err != nil {
		return err
	}
	s.mu.Lock()
	s.renewalCapped = false
	s.byPasskey = false
	s.mu.Unlock()
	return nil
}

// renew presents session_token and nothing else — not the API key, and not
// data_token, which must not be able to extend its own life.
func (s *sessionState) renew(ctx context.Context, c *Client) error {
	s.mu.RLock()
	tok := s.appToken
	s.mu.RUnlock()
	if tok == "" {
		return ErrInvalidSession
	}
	return s.installRenewal(ctx, c, tok)
}

// installRenewal runs a renewal's exchange and records whether it extended
// the session. An expiry no later than the one it replaced means the service
// clamped it to the session's cap: renewing again would change nothing.
func (s *sessionState) installRenewal(ctx context.Context, c *Client, tok string) error {
	s.mu.RLock()
	var previous time.Time
	if s.current != nil {
		previous = s.current.ExpiresAt
	}
	s.mu.RUnlock()
	if err := s.exchange(ctx, c, "/sdk/v1/auth/renew", nil, tok); err != nil {
		return err
	}
	s.mu.Lock()
	if !previous.IsZero() && !s.current.ExpiresAt.After(previous) {
		s.renewalCapped = true
	}
	s.mu.Unlock()
	return nil
}

// exchange issues a token-issuing POST to path — body as its payload, and
// bearer as its Authorization when set — and installs the pair it returns.
// It goes through roundTrip (retry.go): a connection that failed before the
// request was written, and the rate limiter's short Retry-After, are sent
// again; an exchange that was sent is not, because a second one would mint a
// second session.
func (s *sessionState) exchange(ctx context.Context, c *Client, path string, body []byte, bearer string) error {
	resp, err := c.roundTrip(ctx, http.MethodPost, func(actx context.Context, track func(*http.Request) *http.Request) (*http.Response, error) {
		req, rerr := newRequest(actx, c, http.MethodPost, c.opts.Endpoint+path, body)
		if rerr != nil {
			return nil, stopError{rerr}
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		return c.httpClient.Do(track(req))
	})
	if err != nil {
		return fmt.Errorf("culperlink: auth request: %w", err)
	}
	defer drainAndClose(resp)

	var ar tokenPairResponse
	if err := decodeResponse(resp, &ar); err != nil {
		return err // an *APIError: it matches the sentinels and keeps the code
	}
	if ar.SessionToken == "" || ar.DataToken == "" {
		return fmt.Errorf("%w: response did not carry both tokens", ErrInvalidSession)
	}
	session := ar.Session
	// The top-level expires_at is authoritative; a zero in both would keep
	// the client permanently inside its refresh window.
	if !ar.ExpiresAt.IsZero() {
		session.ExpiresAt = ar.ExpiresAt
	}
	if session.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: response carried no expiry", ErrInvalidSession)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.appToken = ar.SessionToken
	s.dataToken = ar.DataToken
	s.current = &session
	return nil
}

func (s *sessionState) token() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.appToken
}

// dataTokenValue is the Data Plane credential. There is no fallback to the
// session token, and there must not be one.
func (s *sessionState) dataTokenValue() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dataToken
}

func (s *sessionState) setSovereignPool(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sovereignPoolID = id
}

func (s *sessionState) sovereignPool() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sovereignPoolID
}

func (s *sessionState) snapshot() *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil
	}
	cp := *s.current
	return &cp
}

// clear drops both tokens together: they are one session.
func (s *sessionState) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appToken, s.dataToken = "", ""
	s.current = nil
	s.renewalCapped = false
	s.byPasskey = false
}

// RotateSession forces re-authentication with the API key. Most callers never
// need it: the client renews automatically near expiry. A client with no API
// key that signed in with a passkey has nothing to re-present: this returns
// ErrMissingAPIKey, and the person signs in again.
func (c *Client) RotateSession(ctx context.Context) error {
	if c.IsClosed() {
		return ErrClientClosed
	}
	c.session.clear()
	return c.session.ensureAuthenticated(ctx, c)
}

// CurrentSession returns the current session, or nil before the first
// authentication. Session.Tunnel is the tunnel's state as of the daemon's
// last reply; TunnelStatus asks the daemon now. In TunnelOff its State is
// "off".
func (c *Client) CurrentSession() *Session {
	s := c.session.snapshot()
	if s == nil {
		return nil
	}
	if c.tunnel == nil {
		s.Tunnel = offStatus()
	} else {
		s.Tunnel = c.tunnel.status()
	}
	return s
}

type apiKeyAuthRequest struct {
	APIKey string `json:"api_key"`
}

// tokenPairResponse is the body of POST /sdk/v1/auth/api-key, POST
// /sdk/v1/auth/renew and POST /sdk/v1/auth/passkey/finish-login (CULPER-469:
// a passkey sign-in ends in the same pair).
type tokenPairResponse struct {
	Session      Session   `json:"session"`
	SessionToken string    `json:"session_token"`
	DataToken    string    `json:"data_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// errorsAsAPI is errors.As for *APIError.
func errorsAsAPI(err error) (*APIError, bool) {
	var api *APIError
	ok := errors.As(err, &api)
	return api, ok
}
