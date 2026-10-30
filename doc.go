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
// This library performs no cryptography of its own. Encrypt, Decrypt and
// Attest serialize their arguments and send them to the service; that service
// holds the payload keys and performs every payload operation. A payload is
// therefore protected against every party except the installation the client
// is configured against, which in a customer-operated deployment is the
// customer's own.
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
// record, which a node holds no credential for. Verify, AuditLog and gateway
// selection carry session_token to Options.Endpoint. No request ever carries
// both, and there is no fallback from one to the other.
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
// running, and nothing is started.
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
// re-selected on the next Data Plane call. Close disconnects the tunnel and
// stops a daemon this client started; a daemon named by DaemonSocket is left
// running.
//
// The daemon's control transport is a Unix socket, so the tunnel modes work
// on Linux and macOS. On Windows, and for an installation with no Data Plane
// node, Options.Tunnel.Mode = TunnelOff is the HTTPS-only client: every call
// goes to Options.Endpoint and no daemon is involved.
//
// # Retry discipline
//
// Requests are retried on a 5xx or a transport error, up to
// Options.MaxRetries times (nil means 3; Retries(0) means none) with
// exponential backoff; a 4xx is returned on the first attempt. Every attempt
// is a new request over a buffered body, so a retried Encrypt never sends an
// empty payload, and every response is read to EOF and closed, so a retry
// loop never leaks a connection (CULPER-331).
package culperlink
