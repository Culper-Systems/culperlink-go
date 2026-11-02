package culperlink

// retry.go — the retry policy (CulperLink CULPER-466, audit findings G-12
// and G-21).
//
// Every request this client sends goes through roundTrip, and roundTrip is
// the whole policy. The same six rules are written in CulperLink's Python
// and TypeScript libraries and its own in-process Go client, and
// CulperLink's conformance scenarios prove them by counting the requests
// that reach the server:
//
//  1. A request whose connection failed before any byte of it was sent —
//     the dial, the TLS handshake, a refused or reset connection — is sent
//     again, whatever its method, up to Options.MaxRetries times. The server
//     never saw it. "Sent" means the request's headers were written
//     (httptrace's WroteHeaders); anything after that counts as sent.
//  2. A GET is sent again on 502, on 504, on a 503 that carries no service
//     error code (a load balancer's), and on a timeout, up to MaxRetries
//     times: verify and the session read change nothing.
//  3. A POST is never sent again once it was sent: not on a 5xx, not on a
//     timeout. attest appends a record, gateways/select writes a routing
//     row, the token exchange mints a session and encrypt uses a nonce, so a
//     second copy is a duplicate, not a retry. Before this rule every 5xx and
//     every transport error was retried for every method, and a refused
//     selection was recorded four times (CulperLink audit finding G-12).
//     Through the daemon, the proxy says in Culperlink-Proxy-Upstream
//     whether the node saw the request (CULPER-467): "not-sent" — the dial
//     into the tunnel failed — is rule 1 and is sent again whatever the
//     method, as is a 407 (a stale proxy token); "sent" is a sent request.
//     Either way the tunnel is asked about and dropped if it is down, and
//     the next attempt or call re-establishes it. A 502 without the header
//     is the node's, and sent.
//  4. A 429 RATE_LIMITED, or a 503 RATE_LIMIT_UNAVAILABLE, is answered by
//     the rate limiter before any handler runs, so the server did nothing.
//     Its Retry-After is honoured once per call, any method: when it is
//     between one second and retryAfterCap, the client waits that long and
//     sends once more. A longer wait, a missing one, or a second such answer
//     is returned as the error, carrying APIError.RetryAfter. This resend is
//     in addition to the MaxRetries budget, and MaxRetries 0 turns it off
//     with every other resend.
//  5. Any other 503 with a service error code (GATEWAY_UNAVAILABLE,
//     ATTESTATION_UNAVAILABLE, GATEWAY_SELECTION_NOT_CONFIGURED, ...) is the
//     service's definitive answer: one attempt, then the error.
//  6. There is no automatic re-authentication. A refused session is
//     returned as ErrInvalidSession on the first answer; the client does not
//     present the API key again on its own.
//
// Every wait — the backoff between transient retries and the Retry-After
// wait — ends early, with the context's error, when the caller's context is
// done, and nothing is retried after the caller's context ended.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// retryAfterCap is the longest Retry-After the client waits out on its own.
// A longer one is returned to the caller, who knows whether it can wait.
const retryAfterCap = 10 * time.Second

// pause waits d or until ctx is done. A variable so the tests can count the
// waits without sleeping through them.
var pause = sleepCtx

// attemptFunc sends one attempt. track must be applied to the request it
// sends, so roundTrip can tell whether the request was written. An error
// wrapped in stopError ends the call without a retry: it did not come from
// the transport.
type attemptFunc func(ctx context.Context, track func(*http.Request) *http.Request) (*http.Response, error)

// stopError is an attempt's failure that is not a transport failure — a
// request that could not be built, a tunnel that could not be established —
// and is returned as it is.
type stopError struct{ err error }

func (e stopError) Error() string { return e.err.Error() }
func (e stopError) Unwrap() error { return e.err }

// notSentError is an attempt that the daemon's proxy refused before anything
// reached the node (CULPER-467). The request's headers were written — to the
// proxy — so the trace calls it sent; this says it was not, and rule 1
// sends it again.
type notSentError struct{ err error }

func (e notSentError) Error() string { return e.err.Error() }
func (e notSentError) Unwrap() error { return e.err }

// roundTrip runs one call under the policy above and returns the response
// the caller should decode, or the transport error of the last attempt.
func (c *Client) roundTrip(ctx context.Context, method string, attempt attemptFunc) (*http.Response, error) {
	transient := 0
	waited := false
	for {
		var sent atomic.Bool
		track := func(req *http.Request) *http.Request {
			trace := &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }}
			return req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		}
		resp, err := attempt(ctx, track)
		if err != nil {
			var stop stopError
			if errors.As(err, &stop) {
				return nil, stop.err
			}
			if ctx.Err() != nil {
				return nil, err
			}
			var notSent notSentError
			retry := !sent.Load() || errors.As(err, &notSent) || (method == http.MethodGet && isTimeout(err))
			if !retry || transient >= c.maxRetries {
				return nil, err
			}
			transient++
			if perr := pause(ctx, backoff(transient-1)); perr != nil {
				return nil, perr
			}
			continue
		}

		if wait, limited := rateLimitWait(resp); limited {
			if waited || c.maxRetries == 0 || wait < time.Second || wait > retryAfterCap {
				return resp, nil
			}
			waited = true
			drainAndClose(resp)
			if perr := pause(ctx, wait); perr != nil {
				return nil, perr
			}
			continue
		}

		if method == http.MethodGet && transientStatus(resp) && transient < c.maxRetries {
			transient++
			drainAndClose(resp)
			if perr := pause(ctx, backoff(transient-1)); perr != nil {
				return nil, perr
			}
			continue
		}
		return resp, nil
	}
}

// isTimeout reports a timeout of the request itself: the client's Timeout,
// or a network deadline.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// maxPeek bounds how much of an error body is read to find its code.
const maxPeek = 64 << 10

// peekCode reads the service's error code from an error response and puts
// the body back for decodeResponse. "" when the body is not the service's
// {"error":{...}} envelope.
func peekCode(resp *http.Response) (code string, retryAfter int) {
	if resp.Body == nil {
		return "", 0
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxPeek))
	rest := resp.Body
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(b), rest), rest}
	var env errorEnvelope
	if json.Unmarshal(b, &env) != nil || env.Error == nil {
		return "", 0
	}
	return env.Error.Code, env.Error.RetryAfter
}

// rateLimitWait reports whether resp is the rate limiter's refusal — 429, or
// 503 RATE_LIMIT_UNAVAILABLE — and the wait it asks for: the Retry-After
// header in seconds, else the envelope's retry_after; zero when it names
// none.
func rateLimitWait(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return 0, false
	}
	code, bodyWait := peekCode(resp)
	if resp.StatusCode == http.StatusServiceUnavailable && code != codeRateLimitUnavailable {
		return 0, false
	}
	secs := retryAfterHeader(resp)
	if secs == 0 {
		secs = bodyWait
	}
	return time.Duration(secs) * time.Second, true
}

// retryAfterHeader is the Retry-After header as whole seconds, or 0 when it
// is absent or not a number of seconds.
func retryAfterHeader(resp *http.Response) int {
	n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After")))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// transientStatus is rule 2's list for a GET: 502, 504, and a 503 that is
// not the service's own answer.
func transientStatus(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return true
	case http.StatusServiceUnavailable:
		code, _ := peekCode(resp)
		return code == ""
	}
	return false
}

// transportClass names a transport failure without its text, which carries
// the URL and the dialled address.
func transportClass(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed"
	}
	return "transport error"
}
