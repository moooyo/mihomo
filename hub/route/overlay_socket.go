package route

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

var (
	overlayControlServer *http.Server
	overlayGenServer     *http.Server
)

// PeerPolicy describes which local process may use a socket.
//
// The design's claim that mihomo's L3/L4 and egress constraints survive a
// complete processor compromise holds only if the compromised processor cannot
// reach the mutation endpoint. That makes the two sockets' separation, and the
// identity check on each, part of the security model rather than hygiene.
type PeerPolicy struct {
	// UID, when non-negative, is the only user id accepted.
	UID int
	// GID, when non-negative, is the only group id accepted.
	GID int
}

// AllowAny is the policy used when no peer identity is configured. It is
// permitted only because the socket itself is mode 0600 in a directory the
// runtime user owns; it is not a substitute for a real policy.
func AllowAny() PeerPolicy { return PeerPolicy{UID: -1, GID: -1} }

func (p PeerPolicy) unrestricted() bool { return p.UID < 0 && p.GID < 0 }

// startOverlayControl serves the coordinator's read-write control socket.
//
// It deliberately does not reuse router(): that mounts /configs, /restart,
// /upgrade and /connections and installs a wildcard CORS middleware, none of
// which belong on a machine-only endpoint.
func startOverlayControl(cfg *Config) {
	if overlayControlServer != nil {
		_ = overlayControlServer.Close()
		overlayControlServer = nil
	}
	if cfg.OverlayControlAddr == "" {
		return
	}
	l, addr, err := listenLocalSocket(cfg.OverlayControlAddr, cfg.OverlayControlPeer)
	if err != nil {
		log.Errorln("Overlay control socket listen error: %s", err)
		return
	}
	log.Infoln("Runtime overlay control socket listening at: %s", addr)

	server := &http.Server{Handler: overlayControlRouter(), ConnContext: withPeerContext}
	overlayControlServer = server
	if err = server.Serve(l); err != nil {
		log.Errorln("Overlay control socket serve error: %s", err)
	}
}

// startOverlayGeneration serves the processor's read-only view.
//
// Separate transport, separate ACL: a read grant must never imply a write
// grant. Placing both on one socket would quietly convert a processor
// compromise into a control-plane compromise.
func startOverlayGeneration(cfg *Config) {
	if overlayGenServer != nil {
		_ = overlayGenServer.Close()
		overlayGenServer = nil
	}
	if cfg.OverlayGenerationAddr == "" {
		return
	}
	l, addr, err := listenLocalSocket(cfg.OverlayGenerationAddr, cfg.OverlayGenerationPeer)
	if err != nil {
		log.Errorln("Overlay generation socket listen error: %s", err)
		return
	}
	log.Infoln("Runtime overlay generation socket listening at: %s", addr)

	server := &http.Server{Handler: overlayGenerationRouter(), ConnContext: withPeerContext}
	overlayGenServer = server
	if err = server.Serve(l); err != nil {
		log.Errorln("Overlay generation socket serve error: %s", err)
	}
}

// listenLocalSocket binds a unix socket with a restrictive mode and wraps it in
// a peer-verifying listener.
//
// The mode is applied by umask around the bind rather than by a chmod
// afterwards. hub/route/server.go's startUnix does the latter — bind, then
// os.Chmod(addr, 0o666) with the error discarded — which both widens the socket
// to every local user and leaves a window in which it carries the process
// umask.
func listenLocalSocket(addr string, policy PeerPolicy) (net.Listener, string, error) {
	resolved := C.Path.Resolve(addr)
	dir := filepath.Dir(resolved)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, resolved, err
	}
	// A stale socket file from a previous process would make bind fail. This
	// is safe because the directory is 0700 and owned by the runtime user.
	if err := syscall.Unlink(resolved); err != nil && !os.IsNotExist(err) {
		log.Debugln("Overlay socket unlink %s: %s", resolved, err)
	}

	restore := setRestrictiveUmask()
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(0)
	l, err := lc.Listen(contextBackground(), "unix", resolved)
	restore()
	if err != nil {
		return nil, resolved, err
	}
	return &peerCheckedListener{Listener: l, policy: policy, path: resolved}, resolved, nil
}

// peerCheckedListener verifies the connecting process on every accept.
//
// Per connection, not once at startup: the socket outlives any single peer, and
// a check performed only at bind time proves nothing about who connects later.
type peerCheckedListener struct {
	net.Listener
	policy PeerPolicy
	path   string
}

func (l *peerCheckedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.policy.unrestricted() {
			return conn, nil
		}
		uid, gid, err := peerCredentials(conn)
		if err != nil {
			log.Warnln("Overlay socket %s: cannot determine peer identity, closing: %s", l.path, err)
			_ = conn.Close()
			continue
		}
		if l.policy.UID >= 0 && uid != l.policy.UID {
			log.Warnln("Overlay socket %s: rejected peer uid %d (want %d)", l.path, uid, l.policy.UID)
			_ = conn.Close()
			continue
		}
		if l.policy.GID >= 0 && gid != l.policy.GID {
			log.Warnln("Overlay socket %s: rejected peer gid %d (want %d)", l.path, gid, l.policy.GID)
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

// peerContextKey carries the verified peer identity from the listener to the
// handler, so a readiness lease records who actually established it rather than
// who claimed to.
type peerContextKey struct{}

type peerIdentity struct{ uid, gid int }

func peerFromContext(ctx context.Context) (uid, gid int) {
	if p, ok := ctx.Value(peerContextKey{}).(peerIdentity); ok {
		return p.uid, p.gid
	}
	return -1, -1
}

// withPeerContext is the http.Server ConnContext hook. It runs once per
// accepted connection, after the listener has already verified the peer against
// the policy.
func withPeerContext(ctx context.Context, conn net.Conn) context.Context {
	uid, gid, err := peerCredentials(conn)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, peerContextKey{}, peerIdentity{uid: uid, gid: gid})
}
