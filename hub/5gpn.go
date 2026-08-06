package hub

import (
	"sync"

	fivegpn "github.com/metacubex/mihomo/5gpn"
	"github.com/metacubex/mihomo/component/updater"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// This file is fork-owned. hub.go carries one call into it.
//
// hub rather than hub/executor, and not by choice: hub/route imports
// hub/executor, and fivegpn imports hub/route to register its API. Starting 5gpn
// from the executor would close that loop. hub is imported only by main, so it
// is the one place in the startup path with no cycle.

var (
	fivegpnOnce     sync.Once
	fivegpnStartErr error
)

// startFiveGPN installs the 5gpn subsystems exactly once, before listeners accept.
//
// Once, because ApplyConfig runs on every reload and the interception engine
// must not be rebuilt with the listeners and resolvers around it -- an operator
// editing an unrelated proxy would otherwise drop every captured session.
//
// DNS is not optional: starting the forwarding plane while the client or origin
// DNS boundary is absent creates an active-looking gateway that cannot carry
// traffic. Startup errors therefore return through hub.Parse. A listener that
// dies later reports through the injected callback and terminates at this one
// process-owner boundary; plugin, interception, and bot errors remain locally
// isolated inside fivegpn.Start.
func startFiveGPN() error {
	fivegpnOnce.Do(func() {
		// 5gpn publishes both core and Console through its digest-pinned installer.
		// Upstream self-updaters cannot preserve the fork or its artifact pins.
		updater.SetManagedDistribution(true)
		fivegpnStartErr = fivegpn.Start(C.Path.HomeDir(), func(err error) {
			log.Fatalln("[5GPN] fatal runtime failure: %v", err)
		})
	})
	return fivegpnStartErr
}
