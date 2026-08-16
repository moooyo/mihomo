package route

import "sync/atomic"

// This file is fork-owned. The upstream restart handler keeps its self-exec
// fallback and calls only the narrow requestProcessRestart seam.

type restartRequestHandler struct {
	request func() bool
}

var processRestartRequest atomic.Pointer[restartRequestHandler]

// SetRestartRequestHandler installs a process-owner seam ahead of the legacy
// self-exec path. Returning true means the request was accepted and the owner
// will perform complete teardown; false preserves ordinary mihomo behavior.
func SetRestartRequestHandler(handler func() bool) {
	if handler == nil {
		processRestartRequest.Store(nil)
		return
	}
	processRestartRequest.Store(&restartRequestHandler{request: handler})
}

func requestProcessRestart() bool {
	handler := processRestartRequest.Load()
	return handler != nil && handler.request != nil && handler.request()
}
