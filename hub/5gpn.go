package hub

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"

	fivegpn "github.com/metacubex/mihomo/5gpn"
	"github.com/metacubex/mihomo/component/updater"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
)

const fivegpnProcessExitDeadline = 30 * time.Second

const (
	fivegpnExitNone int32 = iota
	fivegpnExitRestart
	fivegpnExitFatal
)

// This file is fork-owned. hub.go carries one call into it.
//
// hub rather than hub/executor, and not by choice: hub/route imports
// hub/executor, and fivegpn imports hub/route to register its API. Starting 5gpn
// from the executor would close that loop. hub is imported only by main, so it
// is the one place in the startup path with no cycle.

var (
	fivegpnOnce          sync.Once
	fivegpnStartErr      error
	fivegpnFatalEvents   = make(chan error, 1)
	fivegpnRestartEvents = make(chan struct{}, 1)
	fivegpnFatal         = reportFiveGPNFatal
	fivegpnExitSeverity  atomic.Int32
	fivegpnExitWatchdog  atomic.Bool
	fivegpnHardExit      = func() {
		timer := time.NewTimer(fivegpnProcessExitDeadline)
		defer timer.Stop()
		<-timer.C
		if fivegpnExitSeverity.Load() >= fivegpnExitFatal {
			os.Exit(1)
		}
		os.Exit(0)
	}
)

func reportFiveGPNFatal(err error) {
	if err == nil {
		return
	}
	fivegpnExitSeverity.Store(fivegpnExitFatal)
	select {
	case fivegpnFatalEvents <- err:
	default:
	}
	// A post-up hook or synchronous SIGHUP reload runs on main's event-loop
	// goroutine. Give orderly teardown ample time, but do not let such a caller
	// swallow a critical invariant forever.
	ArmFiveGPNExitWatchdog()
}

func reportFiveGPNRestart() {
	fivegpnExitSeverity.CompareAndSwap(fivegpnExitNone, fivegpnExitRestart)
	select {
	case fivegpnRestartEvents <- struct{}{}:
	default:
	}
	// The controller already returned success. If main is stuck in an operator
	// hook or synchronous reload, bound the wait so the external supervisor can
	// still replace the complete process and rerun container bootstrap.
	ArmFiveGPNExitWatchdog()
}

// ArmFiveGPNExitWatchdog bounds any synchronous startup, reload, hook, or
// shutdown path that prevents main from consuming a queued process-exit event.
// Fatal/restart reporters and the early TERM relay deliberately share this one
// process-wide deadline.
func ArmFiveGPNExitWatchdog() {
	if fivegpnExitWatchdog.CompareAndSwap(false, true) {
		go fivegpnHardExit()
	}
}

// FiveGPNFatalPending lets main upgrade a concurrent TERM/restart outcome and
// its final deferred return code. Fatal severity is monotonic for this process.
func FiveGPNFatalPending() bool { return fivegpnExitSeverity.Load() >= fivegpnExitFatal }

// FiveGPNFatalEvents is the process-owner boundary for a critical runtime
// invariant. Main receives the event and leaves through the same orderly
// shutdown path as SIGTERM; a delayed hard-exit watchdog is only the bound on a
// synchronous operator hook or reload that prevents main from receiving it.
func FiveGPNFatalEvents() <-chan error { return fivegpnFatalEvents }

// FiveGPNRestartEvents carries managed restart requests after the HTTP response
// has been flushed. Exiting lets systemd or Docker replace the complete failure
// domain; syscall.Exec would skip container bootstrap and lifecycle cleanup.
func FiveGPNRestartEvents() <-chan struct{} { return fivegpnRestartEvents }

func prepareFiveGPNDistribution() {
	// Publish the distribution boundary only after the complete managed
	// controller preflight succeeds and before entering the shared runtime
	// failure domain. Once startup begins, an error must not turn a partially
	// initialized 5gpn process back into ordinary mihomo behavior.
	updater.SetManagedDistribution(true)
}

// startFiveGPN installs the 5gpn subsystems exactly once, before listeners accept.
//
// Once, because ApplyConfig runs on every reload and the interception engine
// must not be rebuilt with the listeners and resolvers around it -- an operator
// editing an unrelated proxy would otherwise drop every captured session.
//
// DNS is not optional: starting the forwarding plane while the client or origin
// DNS boundary is absent creates an active-looking gateway that cannot carry
// traffic. Startup errors therefore return through hub.ParseManaged. A
// listener that dies later reports through the injected callback and terminates
// at this one process-owner boundary; plugin, interception, and bot errors
// remain locally isolated inside fivegpn.Start.
func startFiveGPN() error {
	// The controller is part of the same deliberate failure domain as DoT. The
	// route package owns the listener, while hub owns the process, so the fatal
	// action is injected here instead of calling os.Exit from a serving goroutine.
	route.SetControllerFatalHandler(func(err error) { fivegpnFatal(err) })
	route.SetRestartRequestHandler(func() bool {
		reportFiveGPNRestart()
		return true
	})
	fivegpnOnce.Do(func() {
		// 5gpn publishes both core and Console through its digest-pinned installer.
		// Upstream self-updaters cannot preserve the fork or its artifact pins.
		fivegpnStartErr = fivegpn.Start(C.Path.HomeDir(), func(err error) { fivegpnFatal(err) })
	})
	return fivegpnStartErr
}

// Shutdown closes ordinary core listeners, then releases the 5gpn services and
// their workers. Product-owned goroutines and child processes are explicitly
// waited here instead of being left to process exit.
func Shutdown(ctx context.Context) error {
	executor.Shutdown()
	return fivegpn.Shutdown(ctx)
}
