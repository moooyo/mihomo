package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/log"
)

// This file is fork-owned. main.go retains the upstream process setup and
// delegates only the managed runtime's exit arbitration here.

type runtimeExit struct {
	fatal   error
	restart bool
}

func runtimeExitCode(exit runtimeExit) int {
	if exit.fatal != nil || hub.FiveGPNFatalPending() {
		return 1
	}
	return 0
}

func logRuntimeExit(exit runtimeExit) {
	if exit.fatal != nil {
		log.Errorln("[5GPN] fatal runtime failure: %v", exit.fatal)
	}
	if exit.restart {
		log.Infoln("[5GPN] restart requested; exiting for the external supervisor")
	}
}

func relayRuntimeTermination(
	source <-chan os.Signal,
	target chan<- struct{},
	stop <-chan struct{},
	armWatchdog func(),
) {
	select {
	case <-source:
		if armWatchdog != nil {
			armWatchdog()
		}
		select {
		case target <- struct{}{}:
		case <-stop:
		}
	case <-stop:
	}
}

func finishRuntimeExit(shutdown, postDown func()) {
	if shutdown != nil {
		shutdown()
	}
	if postDown != nil {
		postDown()
	}
}

func pollRuntimeExit(term <-chan struct{}, fatal <-chan error, restart <-chan struct{}) (runtimeExit, bool) {
	// Preserve a fatal outcome if it is already known, even when a TERM or
	// restart request arrived in the same startup window.
	select {
	case err := <-fatal:
		return runtimeExit{fatal: err}, true
	default:
	}
	select {
	case <-restart:
		return preferFatal(fatal, runtimeExit{restart: true}), true
	default:
	}
	select {
	case <-term:
		return preferFatal(fatal, runtimeExit{}), true
	default:
		return runtimeExit{}, false
	}
}

func preferFatal(fatal <-chan error, fallback runtimeExit) runtimeExit {
	select {
	case err := <-fatal:
		return runtimeExit{fatal: err}
	default:
		if hub.FiveGPNFatalPending() {
			return runtimeExit{fatal: errors.New("5gpn fatal event is pending")}
		}
		return fallback
	}
}

func shutdownRuntime() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hub.Shutdown(ctx); err != nil {
		log.Errorln("shutdown error: %v", err)
	}
}

func waitForRuntimeExit(
	term <-chan struct{},
	hup <-chan os.Signal,
	fatal <-chan error,
	restart <-chan struct{},
	reload func(),
) runtimeExit {
	for {
		select {
		case <-term:
			return preferFatal(fatal, runtimeExit{})
		case err := <-fatal:
			return runtimeExit{fatal: err}
		case <-restart:
			return preferFatal(fatal, runtimeExit{restart: true})
		case <-hup:
			if reload != nil {
				reload()
			}
		}
	}
}
