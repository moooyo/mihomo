package tunnel

import (
	"sync/atomic"

	"github.com/metacubex/mihomo/component/overlay"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// proxyIndex is a lock-free view of the proxy name set.
//
// It exists because the overlay anchor's Match runs inside configMux's read
// lock and needs to confirm that the adapter it is about to name still
// resolves. Reading the configMux-guarded proxies map from there would be a
// nested RLock, which deadlocks if a writer arrives between the two — Go's
// RWMutex blocks new readers once a writer is waiting.
var proxyIndex atomic.Pointer[map[string]struct{}]

func publishProxyIndex(newProxies map[string]C.Proxy) {
	idx := make(map[string]struct{}, len(newProxies))
	for name := range newProxies {
		idx[name] = struct{}{}
	}
	proxyIndex.Store(&idx)
}

func adapterExists(name string) bool {
	idx := proxyIndex.Load()
	if idx == nil {
		return false
	}
	_, ok := (*idx)[name]
	return ok
}

// overlayManager is the live runtime overlay, or nil when none is configured.
var overlayManager atomic.Pointer[overlay.Manager]

// SetOverlayManager installs the runtime overlay and binds the anchor rules to
// it. Passing nil disables every anchor, which leaves the operator's own rules
// deciding everything.
func SetOverlayManager(m *overlay.Manager) {
	overlayManager.Store(m)
	if m == nil {
		RC.SetOverlayBinding(nil)
		return
	}
	RC.SetOverlayBinding(&RC.Binding{
		Owner:         m.Owner(),
		Holder:        m.Holder(),
		AdapterExists: adapterExists,
	})
}

// OverlayManager returns the live overlay, or nil.
func OverlayManager() *overlay.Manager { return overlayManager.Load() }

// OverlaySnapshot returns the live overlay snapshot, or nil when no overlay is
// configured.
func OverlaySnapshot() *overlay.Snapshot {
	m := overlayManager.Load()
	if m == nil {
		return nil
	}
	return m.Snapshot()
}

// RevokeOverlayGeneration closes every tracked connection and UDP association
// bound to a generation.
//
// This is a sweep, not a barrier. xsync.Map's Range is explicitly not a
// consistent snapshot, so a connection created concurrently can be missed. The
// match path therefore also has to reject the revoked generation — the sweep
// bounds how long already-established work survives, it does not by itself
// guarantee that none does.
func RevokeOverlayGeneration(generationID string) int {
	if generationID == "" {
		return 0
	}
	closed := statistic.DefaultManager.CloseMatching(func(info *statistic.TrackerInfo) bool {
		return info.Metadata != nil && info.Metadata.OverlayGeneration == generationID
	})
	if closed > 0 {
		log.Infoln("[Overlay] revoked generation %s: closed %d established session(s)", generationID, closed)
	}
	return closed
}
