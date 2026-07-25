//go:build !linux

package route

import (
	"errors"
	"net"
)

// peerCredentials has no portable implementation outside Linux.
//
// Returning an error rather than a permissive stub is deliberate: the caller
// closes a connection whose peer it cannot identify, so a platform without
// SO_PEERCRED fails closed. Linux is the production gateway target; elsewhere
// the overlay sockets are usable only with no peer policy configured, which the
// operator has to choose explicitly.
func peerCredentials(net.Conn) (uid, gid int, err error) {
	return 0, 0, errors.New("peer credentials are not available on this platform")
}

// setRestrictiveUmask is a no-op where umask does not exist. On Windows the
// AF_UNIX socket inherits the containing directory's ACL, which listenLocalSocket
// creates with 0700.
func setRestrictiveUmask() func() { return func() {} }

// grantSocketGroup has no meaning where the socket carries no POSIX group.
// A peer policy naming a gid is unusable on such a platform anyway, because
// peerCredentials already fails closed there.
func grantSocketGroup(string, int) error { return nil }
