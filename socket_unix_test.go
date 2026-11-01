//go:build unix

package culperlink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A caller-named DaemonSocket is checked before anything is sent to it
// (G-27): a path that is not a Unix socket, and a socket another user owns,
// are refused, and the daemon behind the socket never sees a request.
func TestCallerNamedSocketMustBeThisUsersSocket(t *testing.T) {
	skipWithoutUnixSockets(t)
	cp := newFakeCP(t)

	notASocket := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(notASocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c := tunnelClient(t, cp, &fakeDaemon{socket: notASocket})
	if err := c.Connect(context.Background()); !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "Unix socket") {
		t.Fatalf("a regular file: %v, want ErrTunnelUnavailable naming the reason", err)
	}

	d := newFakeDaemon(t, "0.2.0")
	prev := currentUID
	currentUID = func() int { return prev() + 1 }
	t.Cleanup(func() { currentUID = prev })
	err := tunnelClient(t, cp, d).Connect(context.Background())
	if !errors.Is(err, ErrTunnelUnavailable) || !strings.Contains(err.Error(), "not owned by this user") {
		t.Fatalf("another user's socket: %v, want ErrTunnelUnavailable naming the reason", err)
	}
	if ops := d.opList(); len(ops) != 0 {
		t.Fatalf("the daemon behind another user's socket received %v; it should have received nothing", ops)
	}
	if n := cp.hit("/sdk/v1/gateways/select"); n != 0 {
		t.Fatalf("selections = %d, want 0: nothing is selected for a daemon that will not be used", n)
	}

	currentUID = prev
	if err := tunnelClient(t, cp, d).Connect(context.Background()); err != nil {
		t.Fatalf("this user's socket: %v", err)
	}
}
