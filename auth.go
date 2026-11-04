package culperlink

// auth.go — passkey sign-in on the SDK surface (CULPER-469; patent claims 2
// and 5, the technical specification's §2.5 "Login (Every Connection)").
//
// TWO WAYS IN. Options.APIKey is the machine-to-machine path, for a program
// with no person present. A passkey is the person's path: BeginPasskeyLogin
// asks the Control Plane for a FIDO2 challenge, the application has its
// platform authenticator sign it with the person present (user
// verification), and FinishPasskeyLogin carries the assertion back and
// installs the SAME control-and-data token pair the API-key exchange
// installs. From then on renewal, Encrypt, the tunnel and Attest are
// identical.
//
// THE LIBRARY HAS NO AUTHENTICATOR. It carries the ceremony and does not run
// it: the options go to the application untouched, and the
// PublicKeyCredential the platform returns comes back as it was given.
//
// A PERSON'S SESSION STAYS A PERSON'S. A passkey-issued session is renewed
// with its session token, as any session is, and is never replaced by an
// API-key exchange: the key names an organisation and the passkey a person,
// and quietly swapping one for the other would change who the calls are made
// as. When renewal is refused, or the session reaches its 12-hour cap, the
// call returns ErrInvalidSession and the person signs in again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// BeginPasskeyLogin asks the Control Plane for a FIDO2 challenge to sign a
// person in: POST /sdk/v1/auth/passkey/begin-login, public, no credential
// sent and no body. The login is discoverable, so nobody is named.
//
// Hand PublicKey to the platform authenticator untouched (in a browser,
// navigator.credentials.get; ASAuthorization on Apple platforms; Windows
// Hello), with user verification, and pass what it returns to
// FinishPasskeyLogin with CeremonyID. The challenge lasts two minutes and is
// taken once.
func (c *Client) BeginPasskeyLogin(ctx context.Context) (*PasskeyLoginChallenge, error) {
	if c.IsClosed() {
		return nil, ErrClientClosed
	}
	var resp passkeyBeginResponse
	if err := c.publicPost(ctx, "/sdk/v1/auth/passkey/begin-login", nil, &resp); err != nil {
		return nil, err
	}
	return &PasskeyLoginChallenge{PublicKey: resp.PublicKey, CeremonyID: resp.CeremonyID}, nil
}

// FinishPasskeyLogin carries the authenticator's assertion back and signs
// in: POST /sdk/v1/auth/passkey/finish-login, public. The answer is the same
// token pair the API-key exchange issues, installed the same way; from here
// the client renews, encrypts, tunnels and attests as the person the passkey
// names.
//
// A refused passkey is an *APIError matching ErrPasskeyDeclined, its Reason
// the server's class (an unknown or expired ceremony is challenge_expired);
// a lapsed installation licence matches ErrLicenceExpired.
func (c *Client) FinishPasskeyLogin(ctx context.Context, ceremonyID string, assertion *PasskeyAssertion) (*Session, error) {
	if c.IsClosed() {
		return nil, ErrClientClosed
	}
	if ceremonyID == "" {
		return nil, errors.New("culperlink: ceremony id required (from BeginPasskeyLogin)")
	}
	if assertion == nil {
		return nil, errors.New("culperlink: assertion required")
	}
	body, err := json.Marshal(passkeyFinishLoginRequest{
		CeremonyID: ceremonyID,
		ID:         assertion.ID,
		RawID:      assertion.RawID,
		Type:       assertion.Type,
		Response: passkeyAssertionResponse{
			ClientDataJSON:    assertion.ClientDataJSON,
			AuthenticatorData: assertion.AuthenticatorData,
			Signature:         assertion.Signature,
			UserHandle:        assertion.UserHandle,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("culperlink: marshal finish-login request: %w", err)
	}
	if err := c.session.signInWithPasskey(ctx, c, body); err != nil {
		return nil, err
	}
	return c.CurrentSession(), nil
}

// BeginPasskeyRegistration starts enrolling another passkey for the person
// this session names: POST /sdk/v1/auth/passkey/begin-registration on the
// session token. Only a passkey-issued session names a person; under an
// API-key session the server answers 403 FORBIDDEN ("registration needs a
// passkey-issued session"). A person's first passkey is enrolled on the
// Management surface, not here. Hand PublicKey to navigator.credentials.create
// or the platform's equivalent and pass the result to
// FinishPasskeyRegistration.
func (c *Client) BeginPasskeyRegistration(ctx context.Context) (*PasskeyRegistrationChallenge, error) {
	var resp passkeyBeginResponse
	if err := c.doRequest(ctx, http.MethodPost, "/sdk/v1/auth/passkey/begin-registration", nil, &resp); err != nil {
		return nil, err
	}
	return &PasskeyRegistrationChallenge{PublicKey: resp.PublicKey, CeremonyID: resp.CeremonyID}, nil
}

// FinishPasskeyRegistration carries the new credential back and returns its
// credential id (base64url). A refused attestation matches
// ErrPasskeyDeclined.
func (c *Client) FinishPasskeyRegistration(ctx context.Context, ceremonyID string, attestation *PasskeyAttestation) (string, error) {
	if ceremonyID == "" {
		return "", errors.New("culperlink: ceremony id required (from BeginPasskeyRegistration)")
	}
	if attestation == nil {
		return "", errors.New("culperlink: attestation required")
	}
	body, err := json.Marshal(passkeyFinishRegistrationRequest{
		CeremonyID: ceremonyID,
		ID:         attestation.ID,
		RawID:      attestation.RawID,
		Type:       attestation.Type,
		Response: passkeyAttestationResponse{
			ClientDataJSON:    attestation.ClientDataJSON,
			AttestationObject: attestation.AttestationObject,
		},
	})
	if err != nil {
		return "", fmt.Errorf("culperlink: marshal finish-registration request: %w", err)
	}
	var resp passkeyFinishRegistrationResponse
	if err := c.doRequest(ctx, http.MethodPost, "/sdk/v1/auth/passkey/finish-registration", body, &resp); err != nil {
		return "", err
	}
	return resp.CredentialID, nil
}

// RemovePasskey removes one of the person's own passkeys (CULPER-472):
// DELETE /sdk/v1/auth/passkey/credentials/{credential_id} on the session
// token. credentialID is the base64url id FinishPasskeyRegistration
// returned; it is path-safe as it stands and is sent unchanged. The server
// ends every other session that passkey issued at once. Removing the passkey
// this session was issued with is allowed: this session keeps running until
// its next renewal, which is then refused (ErrInvalidSession) and the person
// signs in with another passkey. A person may remove their last passkey; the
// installation's operator enrols a new one on the Management API.
//
// Like a POST, the call is not sent again once it reached the server
// (retry.go): had the first one removed the passkey, a repeat would answer
// 404 for a success.
//
// No passkey with that id belonging to this person (an unknown id and
// someone else's alike) is ErrPasskeyNotFound; under an API-key session,
// which names an organisation and not a person, the server answers 403
// FORBIDDEN, an *APIError.
func (c *Client) RemovePasskey(ctx context.Context, credentialID string) error {
	if c.IsClosed() {
		return ErrClientClosed
	}
	if credentialID == "" {
		return errors.New("culperlink: credential id required (the id FinishPasskeyRegistration returned)")
	}
	err := c.doRequest(ctx, http.MethodDelete, "/sdk/v1/auth/passkey/credentials/"+credentialID, nil, nil)
	var api *APIError
	if errors.As(err, &api) && api.StatusCode == http.StatusNotFound && api.Code == "NOT_FOUND" {
		return fmt.Errorf("%w: %w", ErrPasskeyNotFound, api)
	}
	return err
}

// publicPost is a POST with no credential to Options.Endpoint under the
// retry policy: the public begin-login route.
func (c *Client) publicPost(ctx context.Context, path string, body []byte, out any) error {
	resp, err := c.roundTrip(ctx, http.MethodPost, func(actx context.Context, track func(*http.Request) *http.Request) (*http.Response, error) {
		req, rerr := newRequest(actx, c, http.MethodPost, c.opts.Endpoint+path, body)
		if rerr != nil {
			return nil, stopError{rerr}
		}
		return c.httpClient.Do(track(req))
	})
	if err != nil {
		return fmt.Errorf("culperlink: request failed: %w", err)
	}
	defer drainAndClose(resp)
	return decodeResponse(resp, out)
}

// passkeyBeginResponse is the answer of begin-login and begin-registration:
// the WebAuthn options as go-webauthn serialises them, carried untouched.
type passkeyBeginResponse struct {
	PublicKey  json.RawMessage `json:"public_key"`
	CeremonyID string          `json:"ceremony_id"`
}

// passkeyAssertionResponse is "response" inside the finish-login body,
// camelCase as the WebAuthn JSON names it. The server requires every field;
// an absent user handle is sent as "".
type passkeyAssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

// passkeyFinishLoginRequest is ceremony_id beside the PublicKeyCredential
// JSON. The answer is tokenPairResponse.
type passkeyFinishLoginRequest struct {
	CeremonyID string                   `json:"ceremony_id"`
	ID         string                   `json:"id"`
	RawID      string                   `json:"rawId"`
	Type       string                   `json:"type"`
	Response   passkeyAssertionResponse `json:"response"`
}

type passkeyAttestationResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
}

// passkeyFinishRegistrationRequest carries no user id: the credential is
// enrolled for the person the session names.
type passkeyFinishRegistrationRequest struct {
	CeremonyID string                     `json:"ceremony_id"`
	ID         string                     `json:"id"`
	RawID      string                     `json:"rawId"`
	Type       string                     `json:"type"`
	Response   passkeyAttestationResponse `json:"response"`
}

type passkeyFinishRegistrationResponse struct {
	CredentialID string `json:"credential_id"`
}
