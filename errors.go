package culperlink

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors. Check for them with errors.Is.
var (
	// ErrMissingAPIKey is returned by NewClient when Options.APIKey is empty.
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

	// ErrRateLimited is returned when the service's rate limit is exceeded
	// and the retry budget is spent.
	ErrRateLimited = errors.New("culperlink: rate limited")

	// ErrAPIKeyExpired is returned when the API key is genuine but past its
	// expiry (API_KEY_EXPIRED). Distinct from ErrInvalidSession on purpose:
	// retrying and re-authenticating both fail; renewing the key is the only
	// remedy, and the APIError's Message names the route.
	ErrAPIKeyExpired = errors.New("culperlink: API key expired — renew it")

	// ErrLicenceExpired is returned when the installation's own licence has
	// lapsed (LICENCE_EXPIRED, HTTP 403): the token exchange refuses before it
	// reads the API key. Distinct from ErrAPIKeyExpired on purpose: the key
	// may be perfectly good, renewing it changes nothing, and the remedy is
	// the installation operator's. Sessions already issued run to their own
	// expiry. The APIError's Message is the service's instruction.
	ErrLicenceExpired = errors.New("culperlink: the installation's licence has expired")

	// ErrPasskeyDeclined is returned when the user cancels or declines a
	// WebAuthn ceremony on their authenticator.
	ErrPasskeyDeclined = errors.New("culperlink: passkey ceremony declined")

	// ErrSovereignNodeUnavailable is returned when no compliant node can be
	// tunnelled to: gateway selection answered GATEWAY_UNAVAILABLE, or every
	// candidate it offered was offline or outside the geofence this client
	// re-applies.
	ErrSovereignNodeUnavailable = errors.New("culperlink: no compliant sovereign node available")

	// ErrTunnelUnavailable is returned when a Data Plane call cannot be
	// carried by the tunnel: the daemon could not establish or renew it, the
	// daemon could not be found, started or reached, or the installation
	// does not serve gateway selection (an HTTPS-only one wants
	// Options.Tunnel.Mode = TunnelOff). The message carries the daemon's
	// error class; never a token or an address. ErrTunnelDaemonNotFound and
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
// ErrTunnelUnavailable and, when set, a more specific sentinel.
type tunnelError struct {
	kind error // ErrTunnelDaemonNotFound, ErrTunnelDaemonIncompatible, or nil
	msg  string
}

func (e *tunnelError) Error() string { return e.msg }

func (e *tunnelError) Is(target error) bool {
	return target == ErrTunnelUnavailable || (e.kind != nil && target == e.kind)
}

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
	case ErrEncryptionFailed, ErrDecryptionFailed:
		return e.Code == "DECRYPTION_FAILED"
	case ErrKeyEpochRetired:
		return e.Code == "KEY_EPOCH_RETIRED"
	case ErrAPIKeyExpired:
		return e.Code == "API_KEY_EXPIRED"
	case ErrLicenceExpired:
		return e.Code == "LICENCE_EXPIRED"
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
			return env.Error
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Code:       "UNKNOWN",
			Message:    fmt.Sprintf("unexpected HTTP %d", resp.StatusCode),
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
