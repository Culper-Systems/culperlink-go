//go:build !unix

package culperlink

// checkDaemonSocket is skipped where there are no Unix sockets with owners
// to check: on Windows the tunnel modes are not available, and TunnelOff
// involves no daemon (see Options.Tunnel.DaemonSocket).
func checkDaemonSocket(string) error { return nil }
