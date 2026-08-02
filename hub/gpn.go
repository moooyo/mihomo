package hub

import (
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/gpn"
	"github.com/metacubex/mihomo/log"
)

// This file is fork-owned. hub.go carries one call into it.
//
// hub rather than hub/executor, and not by choice: hub/route imports
// hub/executor, and gpn imports hub/route to register its API. Starting gpn
// from the executor would close that loop. hub is imported only by main, so it
// is the one place in the startup path with no cycle.

var gpnOnce sync.Once

// startGPN installs the 5gpn subsystems exactly once, before listeners accept.
//
// Once, because ApplyConfig runs on every reload and the interception engine
// must not be rebuilt with the listeners and resolvers around it -- an operator
// editing an unrelated proxy would otherwise drop every captured session.
//
// Failures are logged, not returned. Everything here is optional relative to
// forwarding: a gateway that cannot read its interception document should still
// resolve and forward, and refusing to boot over it turns a degraded subsystem
// into an outage.
func startGPN() {
	gpnOnce.Do(func() {
		if err := gpn.Start(C.Path.HomeDir()); err != nil {
			log.Errorln("[GPN] start failed, 5gpn features are unavailable: %v", err)
		}
	})
}
