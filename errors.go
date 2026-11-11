package culperlink

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors. Check for them with errors.Is.
var (
	// ErrMissingAPIKey is returned by a call that needs a session when the
	// client has none to use: Options.APIKey is empty and no passkey sign-in
	// has happened (CULPER-469). The message names both ways in.
	ErrMissingAPIKey = errors.New("culperlink: API key required")

	// ErrMissingEndpoint is returned by NewClient when Options.Endpoint is
	// empty. There is deliberately no default: CulperLink is
	// customer-operated, so a fallback to a vendor host would send a
	// misconfigured caller's plaintext to a third party while appearing to
	// work.
	ErrMissingEndpoint = errors.New("culperlink: Options.Endpoint required (set it to your own CulperLink installation, e.g. https://culperlink.internal.example)")

	// ErrInvalidCABundle is returned by NewClient when Options.TLS names a CA
	// bundle that cannot be read or contains no PEM certificate.
	ErrInvalidCABundle = errors.New("culperlink: TLS CA bundle could not be parsed")

	// ErrCertificatePinMismatch is returned when Options.TLS pins SPKI hashes
	// and the chain the service presented contains none of them.
	ErrCertificatePinMismatch = errors.New("culperlink: server certificate did not match any configured SPKI pin")

	// ErrClientClosed is returned by methods called on a Client after Close.
	ErrClientClosed = errors.New("culperlink: client closed")

	// ErrInvalidSession is returned when a token is rejected (expired,
	// revoked or malformed) or a token exchange did not yield a usable pair.
	// It is returned on the first refusal: the client does not present the
	// API key again on its own (retry.go, rule 6).
	ErrInvalidSession = errors.New("culperlink: invalid session")

	// ErrEncryptionFailed matches a failed decrypt, because the service
	// reports that as DECRYPTION_FAILED. A refused Data Plane credential on
	// Encrypt does not match it: that is ErrInvalidSession (CULPER-460 G-14).
	ErrEncryptionFailed = errors.New("culperlink: encryption operation failed")

	// ErrDecryptionFailed is returned by Decrypt when the payload did not
	// authenticate: a tampered ciphertext, a truncated nonce, or a channel
	// that does not match the one bound at encryption. Which of them it was
	// is not disclosed, deliberately.
	ErrDecryptionFailed = errors.New("culperlink: payload did not authenticate")

	// ErrKeyEpochRetired is returned by Decrypt when the key epoch the
	// payload was sealed under is retired. A payload decrypts for at most 13
	// hours after it is sealed (current for 12, one more of grace). Retrying
	// will not help: it is a retention outcome, not a transient failure.
	ErrKeyEpochRetired = errors.New("culperlink: key epoch retired")

	// ErrFIPSBoundary is reserved for operations the service reports as
	// outside its FIPS 140-3 boundary. No method returns it today.
	ErrFIPSBoundary = errors.New("culperlink: operation not in FIPS boundary")

	// ErrRateLimited is returned when the caller is over its rate limit
	// (RATE_LIMITED, HTTP 429). A Retry-After of at most ten seconds is
	// waited out once and the request sent again (retry.go, rule 4); a
	// longer one, or a second refusal, is returned at once with the wait in
	// APIError.RetryAfter.
	ErrRateLimited = errors.New("culperlink: rate limited")

	// ErrRateLimitUnavailable is returned when the installation could not
	// count the request against its rate limit — its Redis was unreachable
	// — and refused it (RATE_LIMIT_UNAVAILABLE, HTTP 503). The caller did
	// nothing wrong: it is a sibling of ErrRateLimited, not the same thing,
	// and the remedy is the installation operator's. The Retry-After (5
	// seconds) is waited out once, as for ErrRateLimited, and a second
	// refusal is returned with APIError.RetryAfter.
	ErrRateLimitUnavailable = errors.New("culperlink: the installation cannot check its rate limit right now")

	// ErrSelectionNotConfigured is returned by Connect, or the first Encrypt
	// or Decrypt, when the installation runs no gateway selection
	// (GATEWAY_SELECTION_NOT_CONFIGURED, HTTP 503): it has no node registry,
	// so no node can be offered to anyone. It is not
	// ErrSovereignNodeUnavailable, which is the organization's policy
	// leaving no eligible node. The remedy is the installation's: deploy its
	// node registry, or set Options.Tunnel.Mode = TunnelOff for an
	// installation that serves encrypt itself.
	ErrSelectionNotConfigured = errors.New("culperlink: gateway selection is not configured on this installation")

	// ErrAPIKeyExpired is returned when the API key is genuine but past its
	// expiry (API_KEY_EXPIRED). Distinct from ErrInvalidSession on purpose:
	// retrying and re-authenticating both fail; renewing the key is the only
	// remedy, and the APIError's Message names the route.
	ErrAPIKeyExpired = errors.New("culperlink: API key expired — renew it")

	// ErrLicenseExpired is returned when the installation's own license has
	// lapsed (LICENSE_EXPIRED, HTTP 403): the token exchange refuses before it
	// reads the API key. Distinct from ErrAPIKeyExpired on purpose: the key
	// may be perfectly good, renewing it changes nothing, and the remedy is
	// the installation operator's. Sessions already issued run to their own
	// expiry. The APIError's Message is the service's instruction.
	ErrLicenseExpired = errors.New("culperlink: the installation's license has expired")

	// ErrPasskeyDeclined matches the server's refusal of a passkey:
	// INVALID_PASSKEY (HTTP 401) from FinishPasskeyLogin or
	// FinishPasskeyRegistration. APIError.Reason carries the class when the
	// server gives one; a bare refusal is also the answer for an unknown
	// credential and a suspended account. A person canceling in the
	// platform authenticator is the platform's error, before this library is
	// called.
	ErrPasskeyDeclined = errors.New("culperlink: passkey refused")

	// ErrPasskeyNotFound is returned by RemovePasskey when no passkey with
	// that id belongs to the person the session names: NOT_FOUND (HTTP 404)
	// from DELETE /sdk/v1/auth/passkey/credentials/{credential_id}
	// (CULPER-472). The server gives the same answer whether the id is
	// unknown or is someone else's, so the surface never says whether a
	// credential exists. A second removal of the same id returns it. The
	// *APIError is reachable through errors.As. Only RemovePasskey wraps its
	// refusal in it: a NOT_FOUND from any other route does not match.
	ErrPasskeyNotFound = errors.New("culperlink: no such passkey for this person")

	// ErrSovereignNodeUnavailable is returned when no compliant node can be
	// tunnelled to: gateway selection answered GATEWAY_UNAVAILABLE, or every
	// candidate it offered was offline or outside the geofence this client
	// re-applies.
	ErrSovereignNodeUnavailable = errors.New("culperlink: no compliant sovereign node available")

	// ErrTunnelUnavailable is returned when a Data Plane call cannot be
	// carried by the tunnel: the daemon could not establish or renew it, the
	// daemon could not be found, started or reached, or the installation
	// does not serve gateway selection (an HTTPS-only one wants
	// Options.Tunnel.Mode = TunnelOff), or a caller-named DaemonSocket is not
	// a Unix socket owned by this user. The message is a fixed prefix, a
	// short class and the service's code when there was one; never a token,
	// a URL, an address or a port. ErrTunnelDaemonNotFound and
	// ErrTunnelDaemonIncompatible both match it as well.
	ErrTunnelUnavailable = errors.New("culperlink: tunnel unavailable")

	// ErrTunnelDaemonNotFound is returned when no culperlink-tunnel daemon
	// could be located. The message names the option that points at one and
	// every place searched, in order. It also matches ErrTunnelUnavailable.
	ErrTunnelDaemonNotFound = errors.New("culperlink: tunnel daemon not found")

	// ErrTunnelDaemonIncompatible is returned when the daemon that answered
	// reports a version outside [DaemonVersionMin, DaemonVersionMax). The
	// message names both versions. It also matches ErrTunnelUnavailable.
	ErrTunnelDaemonIncompatible = errors.New("culperlink: tunnel daemon version incompatible")

	// ErrInvalidTunnelMode is returned by NewClient when Options.Tunnel.Mode
	// is none of TunnelNetstack, TunnelSystem, TunnelOff or empty.
	ErrInvalidTunnelMode = errors.New("culperlink: Options.Tunnel.Mode must be netstack, system or off")
)

// tunnelError is a tunnel failure with its own message that matches
// ErrTunnelUnavailable and, when set, a more specific sentinel. Its message
// is safe to log; cause, when set, is reachable through errors.Is and
// errors.As and is never printed.
type tunnelError struct {
	kind  error // ErrTunnelDaemonNotFound, ErrTunnelDaemonIncompatible, or nil
	msg   string
	cause error
}

func (e *tunnelError) Error() string { return e.msg }

func (e *tunnelError) Is(target error) bool {
	return target == ErrTunnelUnavailable || (e.kind != nil && target == e.kind)
}

func (e *tunnelError) Unwrap() error { return e.cause }

// The service's codes this library names more than once.
const (
	codeRateLimitUnavailable   = "RATE_LIMIT_UNAVAILABLE"
	codeSelectionNotConfigured = "GATEWAY_SELECTION_NOT_CONFIGURED"
)

// tunnelUnavailable is ErrTunnelUnavailable with a detail.
func tunnelUnavailable(format string, args ...any) error {
	return &tunnelError{msg: "culperlink: tunnel unavailable: " + fmt.Sprintf(format, args...)}
}

// APIError is a structured error returned by the service.
type APIError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	TraceID    string `json:"trace_id,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
	// Reason is the server's refusal class on INVALID_PASSKEY (CULPER-468,
	// CULPER-469): one of attestation_unverified, aaguid_not_allowed,
	// user_verification_missing, sign_count_replay, challenge_expired (an
	// unknown or expired ceremony too), no_organization, credential_retired.
	// Empty on every other code, and on a bare refusal. It names a class,
	// never the matched material.
	Reason string `json:"reason,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.TraceID != "" {
		return fmt.Sprintf("culperlink api: %s (%s) — trace=%s", e.Code, e.Message, e.TraceID)
	}
	return fmt.Sprintf("culperlink api: %s (%s)", e.Code, e.Message)
}

// Is maps the service's codes onto the sentinels, so a caller can write
// errors.Is(err, culperlink.ErrInvalidSession) and still reach the code and
// status the service sent through errors.As.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrInvalidSession:
		return e.Code == "INVALID_SESSION" || e.Code == "SESSION_EXPIRED" || e.Code == "UNAUTHORIZED" || e.Code == "INVALID_CREDENTIAL"
	case ErrRateLimited:
		return e.Code == "RATE_LIMITED" || e.StatusCode == http.StatusTooManyRequests
	case ErrRateLimitUnavailable:
		return e.Code == codeRateLimitUnavailable
	case ErrSelectionNotConfigured:
		return e.Code == codeSelectionNotConfigured
	case ErrEncryptionFailed, ErrDecryptionFailed:
		return e.Code == "DECRYPTION_FAILED"
	case ErrKeyEpochRetired:
		return e.Code == "KEY_EPOCH_RETIRED"
	case ErrAPIKeyExpired:
		return e.Code == "API_KEY_EXPIRED"
	case ErrLicenseExpired:
		return e.Code == "LICENSE_EXPIRED"
	case ErrPasskeyDeclined:
		return e.Code == "INVALID_PASSKEY"
	case ErrSovereignNodeUnavailable:
		// Gateway selection wraps its refusal in the sentinel explicitly;
		// from any other request only the service's exact refusal matches.
		return e.Code == "GATEWAY_UNAVAILABLE" && e.Message == "no compliant sovereign node available"
	}
	return false
}

// errorEnvelope is the service's {"error":{...}} shape.
type errorEnvelope struct {
	Error *APIError `json:"error"`
}

// decodeResponse returns *APIError for a status of 400 or more, and
// otherwise decodes the body into out.
func decodeResponse(resp *http.Response, out any) error {
	if resp.StatusCode >= 400 {
		var env errorEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err == nil && env.Error != nil {
			env.Error.StatusCode = resp.StatusCode
			if env.Error.RetryAfter == 0 {
				env.Error.RetryAfter = retryAfterHeader(resp)
			}
			return env.Error
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Code:       "UNKNOWN",
			Message:    fmt.Sprintf("unexpected HTTP %d", resp.StatusCode),
			RetryAfter: retryAfterHeader(resp),
		}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response body: %w", err)
	}
	return nil
}

// timeoutError is a request through the tunnel that timed out. Its message
// names no address; it is not ErrTunnelUnavailable, because the request was
// sent and the node may have acted on it. errors.As finds the transport's
// net.Error, whose Timeout() is true.
type timeoutError struct{ cause error }

func (e *timeoutError) Error() string {
	return "culperlink: the request timed out after it was sent through the tunnel; it is not sent again"
}

func (e *timeoutError) Unwrap() error { return e.cause }
