//go:build unix

package culperlink

import (
	"os"
	"syscall"
)

// daemonSocketOption is the option that names a running daemon's socket;
// quoted in errors.
const daemonSocketOption = "Options.Tunnel.DaemonSocket"

// currentUID is the user id a daemon socket must belong to. A variable so the
// tests can stand in for a socket another user owns, which an unprivileged
// test cannot create.
var currentUID = os.Getuid

// checkDaemonSocket refuses a control socket this client should not hand a
// data token to: a path that is not a Unix socket, or one owned by another
// user id (CulperLink audit finding G-27). The daemon admits only its own
// user or root on its side; this is the client's half, so that a token is
// never written to a socket someone else put at the path. The error names
// neither the path nor its owner.
func checkDaemonSocket(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return tunnelUnavailable("the daemon's control socket cannot be read (%s)", errClass(err))
	}
	if st.Mode()&os.ModeSocket == 0 {
		return tunnelUnavailable("%s does not name a Unix socket; nothing was sent to it", daemonSocketOption)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int64(sys.Uid) != int64(currentUID()) {
		return tunnelUnavailable("the daemon's control socket is not owned by this user; nothing was sent to it")
	}
	return nil
}
