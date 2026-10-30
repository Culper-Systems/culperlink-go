package culperlink

// encrypt.go — the four quickstart operations. Which credential, and which
// host, are two properties (CULPER-419):
//
//   - Encrypt, Decrypt: data_token, through the tunnel to the node.
//   - Attest: data_token, to Options.Endpoint — the receipt is written to the
//     Control Plane's record, which a node cannot reach, and the request
//     names nobody.
//   - Verify: session_token, to Options.Endpoint — it reads the audit log.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Encrypt submits payload to your installation, which encrypts it and returns
// the EncryptedPayload. This library performs no payload cryptography: it
// base64-encodes the payload and sends it through the tunnel.
//
// sessionChannel is an opaque caller-chosen identifier — a conversation,
// document or request id. The service binds it into the AEAD as additional
// authenticated data, and Decrypt must be given the same value.
func (c *Client) Encrypt(ctx context.Context, payload []byte, sessionChannel string) (*EncryptedPayload, error) {
	if len(payload) == 0 {
		return nil, errors.New("culperlink: payload required")
	}
	if sessionChannel == "" {
		return nil, errors.New("culperlink: sessionChannel required")
	}
	body, err := json.Marshal(encryptRequest{
		Payload: base64.StdEncoding.EncodeToString(payload),
		Channel: sessionChannel,
	})
	if err != nil {
		return nil, fmt.Errorf("culperlink: marshal encrypt request: %w", err)
	}
	var resp encryptResponse
	if err := c.doDataRequest(ctx, http.MethodPost, "/sdk/v1/encrypt", body, &resp); err != nil {
		// A refused data token is returned as the *APIError: it matches
		// ErrInvalidSession and keeps the service's code and status. It used
		// to match ErrEncryptionFailed too, so a revoked session looked like
		// an encryption failure (CULPER-460 G-14).
		return nil, err
	}
	out, err := resp.toPayload()
	if err != nil {
		return nil, fmt.Errorf("culperlink: decode encrypted payload: %w", err)
	}
	return out, nil
}

// Decrypt reverses Encrypt. The same sessionChannel must be supplied; a
// mismatch, like any tampering, matches ErrDecryptionFailed. A payload whose
// key epoch is retired matches ErrKeyEpochRetired. Every other failure — a
// rejected session, a rate limit, the tunnel — reaches the caller as itself.
func (c *Client) Decrypt(ctx context.Context, ep *EncryptedPayload, sessionChannel string) ([]byte, error) {
	if ep == nil {
		return nil, errors.New("culperlink: payload required")
	}
	if sessionChannel == "" {
		return nil, errors.New("culperlink: sessionChannel required")
	}
	body, err := json.Marshal(decryptRequest{
		Ciphertext:         base64.StdEncoding.EncodeToString(ep.Ciphertext),
		Nonce:              base64.StdEncoding.EncodeToString(ep.Nonce),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ep.EphemeralPublicKey),
		KeyID:              ep.KeyID,
		Channel:            sessionChannel,
	})
	if err != nil {
		return nil, fmt.Errorf("culperlink: marshal decrypt request: %w", err)
	}
	var resp decryptResponse
	if err := c.doDataRequest(ctx, http.MethodPost, "/sdk/v1/decrypt", body, &resp); err != nil {
		return nil, err
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("culperlink: decode plaintext: %w", err)
	}
	return plaintext, nil
}

// Attest asks your installation to issue a tamper-evident proof that a claim
// was made, without revealing claimBody to the audit reader. Check the proof
// with Verify. Attest does not use the tunnel and does not bring one up.
func (c *Client) Attest(ctx context.Context, claimSubject string, claimBody []byte) (*AttestationProof, error) {
	if claimSubject == "" {
		return nil, errors.New("culperlink: claimSubject required")
	}
	body, err := json.Marshal(attestRequest{
		ClaimSubject: claimSubject,
		ClaimBody:    base64.StdEncoding.EncodeToString(claimBody),
	})
	if err != nil {
		return nil, fmt.Errorf("culperlink: marshal attest request: %w", err)
	}
	var proof AttestationProof
	// Data credential, Control Plane host. The node does not serve this
	// route; do not "make it consistent" with Encrypt.
	if err := c.doControlRequestWithDataToken(ctx, http.MethodPost, "/sdk/v1/attest", body, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// Verify reports whether your installation's audit log records proofHash. It
// is a Control Plane call and does not evaluate the proof locally.
func (c *Client) Verify(ctx context.Context, proofHash string) (bool, error) {
	if proofHash == "" {
		return false, errors.New("culperlink: proofHash required")
	}
	var resp verifyResponse
	path := "/sdk/v1/verify?proof_hash=" + url.QueryEscape(proofHash)
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return false, err
	}
	return resp.Valid, nil
}

type encryptRequest struct {
	Payload string `json:"payload"` // base64
	Channel string `json:"channel"`
}

type encryptResponse struct {
	Ciphertext         string `json:"ciphertext"`
	Nonce              string `json:"nonce"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	KeyID              string `json:"key_id"`
	AAD                string `json:"aad"`
	CUIMarking         string `json:"cui_marking,omitempty"`
}

func (r *encryptResponse) toPayload() (*EncryptedPayload, error) {
	ct, err := base64.StdEncoding.DecodeString(r.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(r.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	epk, err := base64.StdEncoding.DecodeString(r.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	aad, _ := base64.StdEncoding.DecodeString(r.AAD)
	return &EncryptedPayload{
		Ciphertext:         ct,
		Nonce:              nonce,
		EphemeralPublicKey: epk,
		KeyID:              r.KeyID,
		AAD:                aad,
		CUIMarking:         r.CUIMarking,
	}, nil
}

type decryptRequest struct {
	Ciphertext         string `json:"ciphertext"`
	Nonce              string `json:"nonce"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	KeyID              string `json:"key_id"`
	Channel            string `json:"channel"`
}

type decryptResponse struct {
	Plaintext string `json:"plaintext"` // base64
}

type attestRequest struct {
	ClaimSubject string `json:"claim_subject"`
	ClaimBody    string `json:"claim_body"` // base64
}

type verifyResponse struct {
	Valid bool `json:"valid"`
}
