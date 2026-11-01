// Package culperlink is the Go client for CulperLink, the Verifiable Lattice
// Privacy Architecture: a payload is encrypted and decrypted by the
// customer's own CulperLink installation, reached through a post-quantum
// tunnel to its Data Plane node, and every claim about it is checked against
// that installation's audit log.
//
// Quickstart:
//
//	client, err := culperlink.NewClient(culperlink.Options{
//	    APIKey:   os.Getenv("CULPERLINK_API_KEY"),
//	    Endpoint: os.Getenv("CULPERLINK_ENDPOINT"), // your installation; required
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	sealed, err := client.Encrypt(ctx, payload, "conversation-1")
//	...
//	opened, err := client.Decrypt(ctx, sealed, "conversation-1")
//
// The `culperlink-tunnel` daemon from the CulperLink release package must be
// on PATH (or named by Options.Tunnel.DaemonPath); see "The daemon" below.
//
// # Trust boundary
//
// This library performs no payload cryptography. Encrypt, Decrypt and Attest
// serialize their arguments and send them to the service; that service holds
// the payload keys and performs every payload operation. A payload is
// therefore protected against every party except the installation the client
// is configured against, which in a customer-operated deployment is the
// customer's own.
//
// The cryptography this library does do is verifying the Control Plane's
// TLS: the certificate chain against the configured trust (TLSConfig), and,
// when pins are set, a SHA-256 SPKI pin matched against the verified chain
// (tls.go). It uses crypto/tls, crypto/x509 and crypto/sha256 from the
// standard library and implements no primitive itself.
//
// The transport cryptography — the WireGuard tunnel to the Data Plane node,
// keyed by the hybrid ML-KEM-768 + P-256 handshake — is the daemon's. The
// daemon generates and holds the WireGuard key; this library never sees it,
// nor the handshake or lease wire shapes. What this library holds is the
// session's two opaque tokens and a handle on the daemon: its control socket
// path and, when it started the daemon, the process.
//
// # Why a daemon (CULPER-452)
//
// CulperLink's three client libraries — Go, Python and TypeScript — are thin
// clients of one compiled program, `culperlink-tunnel`, shipped as a binary in
// the release package. Until CULPER-452 the Go library embedded the tunnel
// engine instead, which meant compiling it, and the core cryptography under
// it, from source in every customer's build. This library carries no tunnel
// or cryptographic source and imports nothing beyond the standard library;
// the repository's CI fails on any import of the CulperLink core's
// `internal/` or `pkg/culperlink-tunnel` packages. One consequence is that
// this library does not move with the handshake's wire version: the daemon
// does. What this library checks is the daemon's control-protocol version
// (DaemonVersionMin, DaemonVersionMax), before it hands the daemon a token.
//
// # The planes
//
// A CulperLink session is a pair of independent tokens, and which one a
// request carries is decided by where it goes:
//
//	session_token -> Control Plane -> Authorization: Bearer <token>
//	data_token    -> Data Plane    -> X-Culper-Data-Token: <token>
//
// Encrypt and Decrypt carry data_token and nothing else, through the tunnel
// to the node's tunnel address. Attest carries data_token to
// Options.Endpoint: the receipt it writes lives in the Control Plane's
// record, which a node holds no credential for. Verify and gateway selection
// carry session_token to Options.Endpoint. No request ever carries both, and
// there is no fallback from one to the other. AuditLog sends nothing: no
// installation serves an audit view to an SDK credential
// (ErrAuditLogNotServed).
//
// # The daemon
//
// Connect, or the first Encrypt or Decrypt, finds the daemon in this order
// and stops at the first hit:
//
//  1. Options.Tunnel.DaemonPath — an explicit path to the executable;
//  2. PATH — an executable named `culperlink-tunnel`.
//
// A Go module carries no binary, so there is no third, bundled location as
// the Python wheel and the npm package have: the daemon comes from the
// release package's `bin/culperlink-tunnel-<os>-<arch>`, installed on PATH
// as `culperlink-tunnel` (or named directly by DaemonPath). Alternatively
// Options.Tunnel.DaemonSocket names the control socket of a daemon already
// running, and nothing is started. That socket must be a Unix socket owned
// by this process's user, or nothing is sent to it; and one daemon serves
// one client, because a second client's connect replaces the first one's
// tunnel.
//
// A daemon this client starts runs with -exit-with-parent and holds this
// process's end of a pipe as its stdin: it exits when the pipe closes, which
// is Close and equally this process dying without one. Its control socket is
// in a fresh directory only this user can read; its proxies bind loopback on
// kernel-chosen ports, and this client refuses a reported proxy address that
// is not loopback. Every control reply carries the daemon's version, which
// is checked against [DaemonVersionMin, DaemonVersionMax) before the token is
// handed over; a daemon outside it is ErrTunnelDaemonIncompatible.
//
// Then: select (POST /sdk/v1/gateways/select on the Control Plane, carrying
// the sovereign pool and the CUI marking; the geofence the service applied
// is re-applied here, geofence.go), hand the candidate list, the traffic
// policy and data_token to the daemon (op "connect"), and send every Data
// Plane call through the daemon's loopback HTTP proxy to the node's tunnel
// address. A token renewal is followed, in the same call, by a lease renewal
// with the new data_token (op "renew"). A tunnel the daemon reports down is
// re-selected on the next Data Plane call. Errors from this path carry a
// short class and the service's code when there was one, never the node's
// URL, address or port. Close disconnects the tunnel and
// stops a daemon this client started; a daemon named by DaemonSocket is left
// running.
//
// The daemon's control transport is a Unix socket, so the tunnel modes work
// on Linux and macOS. On Windows, and for an installation with no Data Plane
// node, Options.Tunnel.Mode = TunnelOff is the HTTPS-only client: every call
// goes to Options.Endpoint and no daemon is involved.
//
// # Retry policy
//
// A request is sent again only when the server cannot have acted on it, or
// when the request changes nothing (retry.go):
//
//  1. A connection that failed before the request was written — the dial,
//     the TLS handshake, a refused or reset connection — is sent again, any
//     method, up to Options.MaxRetries times.
//  2. A GET is sent again on 502, 504, a 503 with no service error code, and
//     a timeout, up to MaxRetries times.
//  3. A POST that was sent is never sent again: attest appends a record,
//     gateway selection writes a routing row, the token exchange mints a
//     session, encrypt uses a nonce. Through the daemon, the proxy's "upstream
//     unreachable" counts as sent.
//  4. The rate limiter's refusal — 429 RATE_LIMITED, or 503
//     RATE_LIMIT_UNAVAILABLE — is waited out once per call when its
//     Retry-After is at most ten seconds, and the request sent once more. A
//     longer wait, or a second refusal, is returned with APIError.RetryAfter.
//  5. Any other 503 with a service code is definitive.
//  6. A refused session is returned as ErrInvalidSession. The client does not
//     present the API key again on its own.
//
// MaxRetries nil means 3; Retries(0) turns off every resend, rule 4's
// included. Every attempt is a new request over a buffered body, so a resent
// request never sends an empty payload, and every response is read to EOF
// and closed, so a retry loop never leaks a connection (CULPER-331).
package culperlink
