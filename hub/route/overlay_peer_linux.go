//go:build linux

package route

import (
	"errors"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerCredentials reads the connecting process's identity from the kernel via
// SO_PEERCRED. It cannot be spoofed by the peer, which is what makes it usable
// as an authentication mechanism rather than a hint.
func peerCredentials(conn net.Conn) (uid, gid int, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("connection is not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return int(cred.Uid), int(cred.Gid), nil
}

// setRestrictiveUmask narrows the umask so a socket created inside the window
// is 0600, and returns a function restoring the previous value.
//
// Setting the mode this way rather than chmod-ing after bind closes the window
// in which the socket is reachable with whatever the process umask happened to
// be.
func setRestrictiveUmask() func() {
	old := syscall.Umask(0o177)
	return func() { syscall.Umask(old) }
}

// grantSocketGroup hands a bound socket to the group its peer policy admits.
//
// Ordering matters: chown first, chmod second. Widening the mode before the
// owner group is set would leave a window in which the socket is group-writable
// by whatever group it was created with.
func grantSocketGroup(path string, gid int) error {
	if err := os.Chown(path, -1, gid); err != nil {
		return err
	}
	return os.Chmod(path, 0o660)
}
