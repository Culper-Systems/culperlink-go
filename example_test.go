package culperlink_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	culperlink "github.com/culper-systems/culperlink-go"
)

// Example is the quickstart: an API key, your installation's endpoint, and
// the culperlink-tunnel daemon from the release package on PATH. It encrypts
// and decrypts through the tunnel, attests and verifies. Compiled, not run:
// it needs an installation.
func Example() {
	client, err := culperlink.NewClient(culperlink.Options{
		APIKey:   os.Getenv("CULPERLINK_API_KEY"),
		Endpoint: os.Getenv("CULPERLINK_ENDPOINT"),
		// For an installation behind a private CA:
		TLS: culperlink.TLSConfig{CACertFile: os.Getenv("CULPERLINK_CA_FILE")},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Optional: fail fast at startup on a bad key, a missing daemon or no
	// compliant node, rather than on the first payload.
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	sealed, err := client.Encrypt(ctx, []byte("the customer's confidential prompt"), "conversation-1")
	if err != nil {
		log.Fatal(err)
	}
	opened, err := client.Decrypt(ctx, sealed, "conversation-1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(opened))

	if _, err := client.Decrypt(ctx, sealed, "conversation-2"); errors.Is(err, culperlink.ErrDecryptionFailed) {
		fmt.Println("a different channel does not decrypt")
	}

	proof, err := client.Attest(ctx, "document-summary", []byte("hashed-document-fingerprint"))
	if err != nil {
		log.Fatal(err)
	}
	ok, err := client.Verify(ctx, proof.ProofHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("recorded:", ok)

	st := client.CurrentSession().Tunnel
	fmt.Println("tunnel:", st.State, "via", st.Gateway.ID)
}

// ExampleTunnelOptions shows the HTTPS-only client, for an installation with
// no Data Plane node (and for Windows, where the daemon's control transport
// is not implemented).
func ExampleTunnelOptions() {
	client, err := culperlink.NewClient(culperlink.Options{
		APIKey:   os.Getenv("CULPERLINK_API_KEY"),
		Endpoint: os.Getenv("CULPERLINK_ENDPOINT"),
		Tunnel:   culperlink.TunnelOptions{Mode: culperlink.TunnelOff},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()
}
