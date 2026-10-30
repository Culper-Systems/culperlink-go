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
- Mode `TunnelOff` is the HTTPS-only client, for an installation with no
  Data Plane node and for Windows.
