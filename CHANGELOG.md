# Changelog

All notable changes to the CulperLink Go SDK. Versions follow the CulperLink
release this library is published with; the tag is `v<version>`.

## 0.2.0 — unreleased

### Breaking

- The passkey methods are rebuilt for the passkey sign-in the installation
  now serves on the SDK surface (CULPER-469): `BeginPasskeyAuth` and
  `FinishPasskeyAuth` are removed, with `AuthChallenge` and the byte-typed
  `PasskeyAssertion`. Their replacements are `BeginPasskeyLogin` /
  `FinishPasskeyLogin` (the ceremony id and the WebAuthn
  `PublicKeyCredential` JSON, base64url strings as the platform returns them)
  and `BeginPasskeyRegistration` / `FinishPasskeyRegistration`.
- `NewClient` no longer refuses an empty `APIKey`: a call made before either
  way in returns `ErrMissingAPIKey`, whose message names both.

### Added

- Passkey sign-in (CULPER-469; the patent's claims 2 and 5): a person's
  device signs a FIDO2 challenge with the person present, and
  `FinishPasskeyLogin` installs the same control-and-data token pair the API
  key gets. A passkey session is renewed with its session token and never
  replaced by an API-key session. The library carries the ceremony; the
  application's platform authenticator runs it.
- A payload request the node answers 409 (the tunnel changed tenant,
  CULPER-467) tears the tunnel down, connects afresh and is sent once more.
- `RemovePasskey(ctx, credentialID)` (CULPER-472): a person removes one of
  their own passkeys, named by the id `FinishPasskeyRegistration` returned,
  under a passkey-issued session. `ErrPasskeyNotFound` when no passkey with
  that id is theirs; the installation ends every other session that passkey
  issued, and the current session runs until its next renewal.
- `APIError.Reason`: the server's refusal class on `INVALID_PASSKEY` (CULPER-468; `no_organization` and `credential_retired` added by CULPER-469), declared so the error envelope decodes field for field; empty on every other code.

The Go SDK's first release from its own repository (CULPER-452).

- The library is a client of the `culperlink-tunnel` daemon from the
  CulperLink release package, as the Python and TypeScript SDKs are. It finds
  the daemon at `Options.Tunnel.DaemonPath` or on `PATH` (or uses a running
  one at `Options.Tunnel.DaemonSocket`), starts it with `-exit-with-parent`,
  checks its version against `DaemonVersionMin`/`DaemonVersionMax` before
  handing it a token, and refuses a proxy address that is not loopback.
- No payload cryptography and no tunnel code in the library: it verifies the
  installation's TLS (chain and SPKI pins) with the standard library, which
  is its only dependency. The tunnel's hybrid handshake (ML-KEM-768 + P-384
  since CulperLink CULPER-467; P-256 before) is the daemon's, so this library
  needed no change for the curve.
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
- CUI marking is the service's, bound into the ciphertext (CulperLink
  CULPER-462, owner decision 22). `TagPayload` now sends its marking as the
  encrypt request's `cui_marking`; the service seals the payload under the
  stronger of it and the organisation's default marking (set by the
  installation's operator) and returns the marking it applied, which
  `EncryptedPayload.CUIMarking` now carries. `Encrypt` sends none, so the
  default applies. The marking is in the payload's associated data:
  `Decrypt` sends it back with the new `EncryptedPayload.PayloadVersion`
  (2), and a payload whose marking was stripped or changed matches
  `ErrDecryptionFailed`. The service refuses payload format version 1 by
  name. All nineteen recognised markings are constants;
  `RequiresSovereignNode` answers per marking (true only for SP-CTI,
  SP-EXPT, SP-NUC, SP-NNPI, SP-INTEL, SP-LEI, SP-ECI and SP-CRIT); the
  client-side geofence covers SP-ECI (ITAR) and SP-NNPI and SP-INTEL
  (GovCloud).
- Audit fix batch 11 (CulperLink CULPER-466), before the first publish:
  - one retry policy, the same in all four CulperLink clients (G-12, G-21):
    a request is sent again only when the connection failed before it was
    written, or when it is a `GET` that met a 502, 504, a code-less 503 or a
    timeout. A `POST` that was sent is never sent again, so `Attest` no
    longer writes duplicate records and a refused gateway selection is
    recorded once. The rate limiter's `Retry-After` is honoured once per call
    when it is ten seconds or less. A 503 with a service code is final. The
    "respects Retry-After" and "retry budget is spent" sentences are now
    true or gone. A request that met a dead tunnel is no longer resent in the
    same call; the next call re-establishes the tunnel;
  - new `ErrRateLimitUnavailable` (`RATE_LIMIT_UNAVAILABLE`, 503) and
    `ErrSelectionNotConfigured` (`GATEWAY_SELECTION_NOT_CONFIGURED`, 503,
    which the server used to send as `GATEWAY_UNAVAILABLE`, G-32);
    `APIError.RetryAfter` is read from the `Retry-After` header when the body
    names none;
  - `Options.Tunnel.DaemonSocket` must be a Unix socket owned by your user,
    checked before anything is sent to it (G-27); errors from the daemon path
    never carry a URL, an address or a port (G-26).
- Audit fix batch 12 (CulperLink CULPER-467), before the first publish:
  - the daemon's proxies require a token (audit B2-3): this library reads
    `proxy_token` from the daemon's status and presents it as the proxy
    password on every Data Plane request. A daemon that reports none is
    refused (`ErrTunnelUnavailable`, "no proxy token"); a 407 — a restarted
    daemon's new token — sent nothing and is answered by reading the token
    again. Needs the daemon from the same release;
  - the proxy's 502 now says whether the request reached the node
    (`Culperlink-Proxy-Upstream`): `not-sent` is sent again, any method, on
    a re-established tunnel, so an `Encrypt` that met a tunnel that had just
    dropped succeeds instead of failing; `sent` is a sent request and a
    `POST` is not sent again ("the tunnel failed after the request was
    sent"). This replaces batch 11's "a request that met a dead tunnel is
    no longer resent in the same call", which held only because the proxy
    could not say.
- Mode `TunnelOff` is the HTTPS-only client, for an installation with no
  Data Plane node and for Windows.
