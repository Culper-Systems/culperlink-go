# Changelog

All notable changes to the CulperLink Go SDK. Versions follow the CulperLink
release this library is published with; the tag is `v<version>`.

## 0.2.0 — unreleased

The Go SDK's first release from its own repository (CULPER-452).

- The library is a client of the `culperlink-tunnel` daemon from the
  CulperLink release package, as the Python and TypeScript SDKs are. It finds
  the daemon at `Options.Tunnel.DaemonPath` or on `PATH` (or uses a running
  one at `Options.Tunnel.DaemonSocket`), starts it with `-exit-with-parent`,
  checks its version against `DaemonVersionMin`/`DaemonVersionMax` before
  handing it a token, and refuses a proxy address that is not loopback.
- No payload cryptography and no tunnel code in the library: it verifies the
  installation's TLS (chain and SPKI pins) with the standard library, which
  is its only dependency. The tunnel's hybrid handshake (ML-KEM-768 + P-256) is
  the daemon's.
- `go get github.com/culper-systems/culperlink-go@v0.2.0`; the package is
  `culperlink`. Earlier Go SDK code lived inside the CulperLink core
  repository at a different path and was never published; nothing carries
  over and there is nothing to migrate.
- New: `ErrTunnelDaemonNotFound`, `ErrTunnelDaemonIncompatible` (both also
  match `ErrTunnelUnavailable`), `Client.TunnelStatus`, `TunnelStatus.DaemonPID`.
- Audit fix batches 5 and 6 (CulperLink CULPER-460, CULPER-461), before the
  first publish, so nothing here is a change for an existing user:
  - the SPKI pin is matched only against the verified certificate chain,
    never a certificate the server merely presented (G-2);
  - `TunnelPolicy.IPv6` reaches the daemon (G-4); a session at its
    twelve-hour cap renews once (G-5); the API key is redacted in every
    printed form of `Options` and `*Client` (G-11);
  - `Options.MaxRetries` is `*int`: nil means 3, `Retries(0)` means none
    (G-30); Encrypt keeps the service's error code (G-14);
  - wire types match the server exactly: `LatencyMillis` and the
    per-candidate `TunnelPolicy` are gone, the four `Score*` fields and
    `AttestedAt` are present (G-20, G-33);
  - new `ErrLicenceExpired` (G-13) and `ErrAuditLogNotServed`, returned by
    `AuditLog` because no `/sdk/v1` route serves an audit view (G-10);
  - the library is a runner in CulperLink's conformance suite and its
    end-to-end test runs in that repository's CI (G-7).
- Mode `TunnelOff` is the HTTPS-only client, for an installation with no
  Data Plane node and for Windows.
