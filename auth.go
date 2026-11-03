package culperlink

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// BeginPasskeyAuth starts a WebAuthn authentication ceremony for an end user.
//
// NOT YET SERVED: the installation does not register /sdk/v1/auth/begin or
// /sdk/v1/auth/finish, so this returns an *APIError with status 404. The
// server's passkey ceremonies (CULPER-468) are on the Management surface; the
// SDK-surface sign-in that returns the control and data token pair to a
// person's device is CULPER-469 (patent claims 2 and 5), which rebuilds this
// method as a discoverable login keyed by ceremony id. Until then,
// authenticate with an API key, the machine-to-machine path. The method is
// kept for the patent's client flow; its wire shape will change.
func (c *Client) BeginPasskeyAuth(ctx context.Context, username string) (*AuthChallenge, error) {
	if username == "" {
		return nil, errors.New("culperlink: username required")
	}
	body, err := json.Marshal(beginAuthRequest{Username: username})
	if err != nil {
		return nil, fmt.Errorf("culperlink: marshal begin auth request: %w", err)
	}
	var resp beginAuthResponse
	if err := c.doRequest(ctx, http.MethodPost, "/sdk/v1/auth/begin", body, &resp); err != nil {
		return nil, err
	}
	challenge, err := base64.StdEncoding.DecodeString(resp.Challenge)
	if err != nil {
		return nil, fmt.Errorf("culperlink: decode challenge: %w", err)
	}
	return &AuthChallenge{
		Challenge:        challenge,
		RelyingPartyID:   resp.RelyingPartyID,
		AllowCredentials: resp.AllowCredentials,
		Timeout:          resp.Timeout,
	}, nil
}

// FinishPasskeyAuth completes the ceremony BeginPasskeyAuth started. NOT
// YET SERVED (CULPER-469); see BeginPasskeyAuth.
func (c *Client) FinishPasskeyAuth(ctx context.Context, username string, assertion *PasskeyAssertion) (*Session, error) {
	if username == "" {
		return nil, errors.New("culperlink: username required")
	}
	if assertion == nil {
		return nil, errors.New("culperlink: assertion required")
	}
	body, err := json.Marshal(finishAuthRequest{
		Username:          username,
		CredentialID:      base64.StdEncoding.EncodeToString(assertion.CredentialID),
		AuthenticatorData: base64.StdEncoding.EncodeToString(assertion.AuthenticatorData),
		ClientDataJSON:    base64.StdEncoding.EncodeToString(assertion.ClientDataJSON),
		Signature:         base64.StdEncoding.EncodeToString(assertion.Signature),
		UserHandle:        base64.StdEncoding.EncodeToString(assertion.UserHandle),
	})
	if err != nil {
		return nil, fmt.Errorf("culperlink: marshal finish auth request: %w", err)
	}
	var resp finishAuthResponse
	if err := c.doRequest(ctx, http.MethodPost, "/sdk/v1/auth/finish", body, &resp); err != nil {
		if errors.Is(err, ErrPasskeyDeclined) {
			return nil, fmt.Errorf("%w: %w", ErrPasskeyDeclined, err)
		}
		return nil, err
	}
	c.session.setEndUserToken(resp.SessionToken)
	return &resp.Session, nil
}

type beginAuthRequest struct {
	Username string `json:"username"`
}

type beginAuthResponse struct {
	Challenge        string   `json:"challenge"` // base64
	RelyingPartyID   string   `json:"rp_id"`
	AllowCredentials []string `json:"allow_credentials,omitempty"`
	Timeout          int      `json:"timeout"`
}

type finishAuthRequest struct {
	Username          string `json:"username"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"user_handle,omitempty"`
}

type finishAuthResponse struct {
	Session      Session `json:"session"`
	SessionToken string  `json:"session_token"`
}
