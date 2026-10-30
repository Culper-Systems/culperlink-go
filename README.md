# CulperLink Go SDK

The Go client for [CulperLink](https://culpersystems.com): encrypt and decrypt
payloads through your own CulperLink installation, over a post-quantum tunnel
to its Data Plane node, and attest and verify claims against that
installation's audit log.

This library performs no cryptography and carries no tunnel code. It talks
HTTPS to your installation's Control Plane for the session and for
attestation, and drives the `culperlink-tunnel` daemon — the compiled program
in the CulperLink release package — for the tunnel. It depends on the Go
standard library only.

## Requirements

- **Go 1.26 or newer.**
- **Linux or macOS** for the tunnel. On Windows, or against an installation
  with no Data Plane node, use the HTTPS-only mode (`TunnelOff`, below).
- **The `culperlink-tunnel` daemon** from the CulperLink release package you
  received, on `PATH`. The package carries one per platform as
  `bin/culperlink-tunnel-<os>-<arch>`; install yours under the plain name:

  ```sh
  sudo install -m 0755 culperlink-0.2.0/bin/culperlink-tunnel-linux-amd64 /usr/local/bin/culperlink-tunnel
  ```

  (or set `Options.Tunnel.DaemonPath` to the file). Verify the package's
  signature first — `docs/release/verifying-a-release.md` inside it.

## Install

```sh
go get github.com/culper-systems/culperlink-go@v0.2.0
```

The tag follows the CulperLink release: use the version of the release
package your daemon came from.

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	culperlink "github.com/culper-systems/culperlink-go"
)

func main() {
	client, err := culperlink.NewClient(culperlink.Options{
		APIKey:   os.Getenv("CULPERLINK_API_KEY"),
		Endpoint: os.Getenv("CULPERLINK_ENDPOINT"), // your installation; required
		// For an installation behind a private CA:
		TLS: culperlink.TLSConfig{CACertFile: os.Getenv("CULPERLINK_CA_FILE")},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()

	sealed, err := client.Encrypt(ctx, []byte("the confidential prompt"), "conversation-1")
	if err != nil {
		log.Fatal(err)
	}
	opened, err := client.Decrypt(ctx, sealed, "conversation-1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(opened))

	proof, err := client.Attest(ctx, "document-summary", []byte("document fingerprint"))
	if err != nil {
		log.Fatal(err)
	}
	ok, err := client.Verify(ctx, proof.ProofHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("recorded:", ok)
}
```

The first `Encrypt` (or an explicit `client.Connect(ctx)`) authenticates,
starts the daemon, selects a node and brings the tunnel up; `Close` takes it
down and stops the daemon. Nothing else is configured.

## How it works

| Call | Credential | Goes to |
| --- | --- | --- |
| `Encrypt`, `Decrypt` | `data_token` only | the node's tunnel address, through the daemon |
| `Attest` | `data_token` only | `Options.Endpoint` |
| `Verify`, gateway selection | `session_token` only | `Options.Endpoint` |

The two tokens are independent; no request carries both, and there is no
fallback from one to the other.

`AuditLog` returns `ErrAuditLogNotServed` and sends nothing. No CulperLink
installation serves an audit view to an SDK credential: the auditor views
are at `/api/v1/audit/v1/*` on your installation's operator console, behind
an operator's login.

The daemon is found at `Options.Tunnel.DaemonPath`, else on `PATH`; or
`Options.Tunnel.DaemonSocket` names one already running. A daemon this
library starts gets a control socket in a directory only your user can read,
loopback-only proxies, and `-exit-with-parent`: it exits when your process
closes the client or dies. Before handing it a token, the library checks the
version the daemon reports against the range it was written for
(`DaemonVersionMin`–`DaemonVersionMax`, currently `0.2.0` to below `0.3.0`).

This library does not change when the tunnel's handshake does; the daemon
does. Upgrade the daemon and this library to the same CulperLink release.

## Errors

Check with `errors.Is`; `errors.As(err, &apiErr)` with `*culperlink.APIError`
gives the service's code and HTTP status.

| Error | Meaning |
| --- | --- |
| `ErrTunnelDaemonNotFound` | no daemon at `DaemonPath` or on `PATH`; the message lists where it looked |
| `ErrTunnelDaemonIncompatible` | the daemon's version is outside the supported range; the message names both versions |
| `ErrTunnelUnavailable` | the tunnel could not be established, renewed or used (both errors above also match it) |
| `ErrSovereignNodeUnavailable` | no compliant node: none in your pool, or none inside the geofence |
| `ErrDecryptionFailed` | the payload did not authenticate (tampered, or a different channel) |
| `ErrKeyEpochRetired` | the payload's key epoch is retired; payloads decrypt for at most 13 hours |
| `ErrInvalidSession`, `ErrAPIKeyExpired`, `ErrRateLimited` | as named; an expired key must be renewed, not retried |
| `ErrLicenceExpired` | your installation's licence has lapsed: the key may be fine, and the installation's operator renews the licence |

## HTTPS-only mode

```go
culperlink.Options{..., Tunnel: culperlink.TunnelOptions{Mode: culperlink.TunnelOff}}
```

Every call goes to `Options.Endpoint` and no daemon is involved. For an
installation with no Data Plane node, and for Windows. An installation that
serves a tunnel refuses payload calls on its public address, so this mode
against one fails with a 404 rather than sending payloads the wrong way.

## Licence

See [LICENSE](LICENSE).
