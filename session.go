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

	appToken     string // session_token: Control Plane calls
	dataToken    string // data_token: Data Plane calls
	endUserToken string // from a passkey ceremony; supersedes appToken on the Control Plane

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
// exchange when renewal fails for any reason.
func (s *sessionState) ensureAuthenticated(ctx context.Context, c *Client) error {
	if s.fresh() {
		return nil
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if s.fresh() {
		return nil
	}
	// A capped session cannot be extended: renewing again would only return
	// the same expiry, so go straight to the API key.
	if s.canRenew() && !s.capped() {
		if err := s.renew(ctx, c); err == nil {
			return c.afterTokenRotation(ctx)
		}
	}
	if err := s.authenticate(ctx, c); err != nil {
		return err
	}
	return c.afterTokenRotation(ctx)
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
	req, err := newRequest(ctx, c, http.MethodPost, c.opts.Endpoint+"/sdk/v1/auth/api-key", body)
	if err != nil {
		return err
	}
	if err := s.exchange(c, req); err != nil {
		return err
	}
	s.mu.Lock()
	s.renewalCapped = false
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
	req, err := newRequest(ctx, c, http.MethodPost, c.opts.Endpoint+"/sdk/v1/auth/renew", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return s.installRenewal(c, req)
}

// installRenewal runs a renewal's exchange and records whether it extended
// the session. An expiry no later than the one it replaced means the service
// clamped it to the session's cap: renewing again would change nothing.
func (s *sessionState) installRenewal(c *Client, req *http.Request) error {
	s.mu.RLock()
	var previous time.Time
	if s.current != nil {
		previous = s.current.ExpiresAt
	}
	s.mu.RUnlock()
	if err := s.exchange(c, req); err != nil {
		return err
	}
	s.mu.Lock()
	if !previous.IsZero() && !s.current.ExpiresAt.After(previous) {
		s.renewalCapped = true
	}
	s.mu.Unlock()
	return nil
}

// exchange issues a token-issuing request and installs the pair it returns.
func (s *sessionState) exchange(c *Client, req *http.Request) error {
	resp, err := c.httpClient.Do(req)
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
	if s.endUserToken != "" {
		return s.endUserToken
	}
	return s.appToken
}

// dataTokenValue is the Data Plane credential. There is no fallback to the
// session token, and there must not be one.
func (s *sessionState) dataTokenValue() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dataToken
}

func (s *sessionState) setEndUserToken(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endUserToken = t
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
	s.appToken, s.dataToken, s.endUserToken = "", "", ""
	s.current = nil
	s.renewalCapped = false
}

// RotateSession forces re-authentication with the API key. Most callers never
// need it: the client renews automatically near expiry.
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

// tokenPairResponse is the body of POST /sdk/v1/auth/api-key and POST
// /sdk/v1/auth/renew.
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
