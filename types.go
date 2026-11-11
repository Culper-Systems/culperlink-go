package culperlink

import (
	"encoding/json"
	"time"
)

// Session is an authenticated session, returned for inspection. Neither token
// is exposed.
//
// There is no customer or organization field, deliberately: the service would
// have to disclose the organization's identifier to fill it, and a client
// that holds one tends to echo it back. Tier says what this caller may do,
// not who it is.
type Session struct {
	// ID is a stable identifier for the session, safe to log. It survives
	// renewal.
	ID string `json:"id"`

	// Tier is the contracted tier: TierSovereign, TierEnterprise or
	// TierAIInfrastructure.
	Tier string `json:"tier"`

	// IssuedAt is when the session was authenticated. Renewal does not move
	// it.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is when the current token pair expires. The client renews
	// automatically within five minutes of it.
	ExpiresAt time.Time `json:"expires_at"`

	// Tunnel is the Data Plane transport's state as of the daemon's last
	// reply, filled by CurrentSession. It is this client's, not the
	// service's.
	Tunnel *TunnelStatus `json:"-"`
}

// Tier values: the complete set. The service refuses a Data Plane request
// whose session carries anything else, so a switch over these three needs no
// branch for an unknown tier. "Enterprise+" is the product's display name;
// "enterprise" is the value.
const (
	TierSovereign        = "sovereign"
	TierEnterprise       = "enterprise"
	TierAIInfrastructure = "ai_infrastructure"
)

// EncryptedPayload is the result of Encrypt: everything Decrypt needs to hand
// back to the service, and nothing that reconstructs the plaintext. The SDK
// treats EphemeralPublicKey and KeyID as opaque and echoes them unmodified.
type EncryptedPayload struct {
	Ciphertext         []byte `json:"ciphertext"`
	Nonce              []byte `json:"nonce"`
	EphemeralPublicKey []byte `json:"ephemeral_public_key"`
	KeyID              string `json:"key_id"`
	AAD                []byte `json:"aad,omitempty"`
	// CUIMarking is the Controlled Unclassified Information marking the
	// service sealed the payload under — the organization's default, or a
	// stronger one the request asked for — and "" for none. It is bound into
	// the associated data: Decrypt sends it back, and a payload whose marking
	// was stripped or changed does not decrypt.
	CUIMarking string `json:"cui_marking,omitempty"`
	// PayloadVersion is the payload format version, 2: associated data
	// binding the marking and the channel. Decrypt sends it back; the
	// service refuses version 1 by name.
	// A payload built by hand with no version is sent as version 2.
	PayloadVersion int `json:"payload_version"`
}

// AttestationProof is returned by Attest: a tamper-evident hash issued by the
// installation, checked with Verify against the same installation's audit
// log.
type AttestationProof struct {
	ProofHash    string    `json:"proof_hash"`
	IssuedAt     time.Time `json:"issued_at"`
	AuditLogURL  string    `json:"audit_log_url"`
	ClaimSubject string    `json:"claim_subject"`
}

// GatewayDescriptor is a Data Plane node as gateway selection offers it.
// Everything here is public information about a node; there is no key
// material of any kind. Its fields are the server's candidate, field for
// field, held there by the CulperLink repository's wire-type test
// (internal/sdkapi/wiretypes_test.go, CULPER-461 G-20).
type GatewayDescriptor struct {
	ID           string  `json:"id"`
	Region       string  `json:"region"`
	Country      string  `json:"country"`
	City         string  `json:"city"`
	Status       string  `json:"status"` // "online", "degraded" or "offline"
	IsSovereign  bool    `json:"is_sovereign"`
	IsGovCloud   bool    `json:"is_gov_cloud"`
	ITAREligible bool    `json:"itar_eligible"`
	Load         float64 `json:"load"`
	// The four tunnel facts the daemon needs: where the handshake is served
	// over TLS (the payload surface inside the tunnel listens on the same
	// port), the WireGuard listener, the node's static public key, and the
	// SPKI pin of the handshake listener.
	HandshakeEndpoint  string `json:"handshake_endpoint"`
	WireGuardEndpoint  string `json:"wireguard_endpoint"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
	SPKIPin            string `json:"spki_pin"`
	// Score is the installation's ranking of this candidate, higher first,
	// in [0, 1]: one minus the four weighted costs below.
	Score          float64 `json:"score"`
	ScoreLoad      float64 `json:"score_load"`
	ScoreProximity float64 `json:"score_proximity"`
	ScoreLatency   float64 `json:"score_latency"`
	ScoreHealth    float64 `json:"score_health"`
}

// TunnelPolicy is the organization's traffic policy as gateway selection
// returns it: which prefixes ride the tunnel and where DNS goes. Absent means
// node_only with the host's DNS. It is passed to the daemon, which enforces
// it.
type TunnelPolicy struct {
	Mode     string          `json:"mode"` // "node_only", "prefixes" or "full"
	Prefixes []string        `json:"prefixes,omitempty"`
	DNS      TunnelDNSPolicy `json:"dns"`
	// IPv6 says whether the policy covers IPv6 as well: ::/0 in "full" mode,
	// IPv6 prefixes in "prefixes". It is handed to the daemon; without it a
	// full policy with ipv6 on planned no ::/0, and the node's matching offer
	// of ::/0 was refused as a policy mismatch (CULPER-460 G-4).
	IPv6 bool `json:"ipv6"`
}

// TunnelDNSPolicy is the DNS half of TunnelPolicy: "host" leaves the host's
// resolver alone; "tunnel" sends lookups through the tunnel to Resolvers.
type TunnelDNSPolicy struct {
	Mode      string   `json:"mode"`
	Resolvers []string `json:"resolvers,omitempty"`
}

// PasskeyLoginChallenge is what BeginPasskeyLogin returns. PublicKey is the
// WebAuthn PublicKeyCredentialRequestOptions exactly as the server sent
// them, for the application's platform authenticator; CeremonyID is quoted
// back to FinishPasskeyLogin.
type PasskeyLoginChallenge struct {
	PublicKey  json.RawMessage
	CeremonyID string
}

// PasskeyRegistrationChallenge is what BeginPasskeyRegistration returns: the
// WebAuthn PublicKeyCredentialCreationOptions as sent, and the ceremony id
// FinishPasskeyRegistration quotes.
type PasskeyRegistrationChallenge struct {
	PublicKey  json.RawMessage
	CeremonyID string
}

// PasskeyAssertion is the PublicKeyCredential the authenticator returned for
// a login, as its JSON gives it: every value a base64url string, passed
// through unchanged. ClientDataJSON, AuthenticatorData, Signature and
// UserHandle are its response.* fields; Type is "public-key".
type PasskeyAssertion struct {
	ID                string
	RawID             string
	Type              string
	ClientDataJSON    string
	AuthenticatorData string
	Signature         string
	UserHandle        string
}

// PasskeyAttestation is the PublicKeyCredential the authenticator returned
// for a registration (navigator.credentials.create), as its JSON gives it.
type PasskeyAttestation struct {
	ID                string
	RawID             string
	Type              string
	ClientDataJSON    string
	AttestationObject string
}
