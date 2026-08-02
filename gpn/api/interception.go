package api

import (
	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// SnapshotSource is what the interception routes read from. The façade
// installs it once the engine is up.
//
// An indirection rather than a direct import of gpn/engine because this package
// must not depend on the engine existing: the routes register at init, and a
// gateway whose interception document failed to load still serves its API. The
// nil case is a 503 with a reason, not a missing route.
type SnapshotSource func() (any, error)

var interceptionSource func() SnapshotSource

// SetInterceptionSource installs the reader. Passing nil withdraws it.
func SetInterceptionSource(get SnapshotSource) {
	mu.Lock()
	defer mu.Unlock()
	if get == nil {
		interceptionSource = nil
		return
	}
	interceptionSource = func() SnapshotSource { return get }
}

func currentInterceptionSource() SnapshotSource {
	mu.RLock()
	defer mu.RUnlock()
	if interceptionSource == nil {
		return nil
	}
	return interceptionSource()
}

func interceptionRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)
	r.Get("/", getInterception)
	return r
}

func getInterception(w http.ResponseWriter, r *http.Request) {
	get := currentInterceptionSource()
	if get == nil {
		// Distinguishable from "interception is off". Off is a document that
		// loaded and says enabled: false; this is a document that did not load,
		// and rendering it as off would tell the operator their configuration is
		// being honoured when it is not being read.
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, render.M{"message": "interception engine is not installed"})
		return
	}
	snapshot, err := get()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, render.M{"message": err.Error()})
		return
	}
	render.JSON(w, r, snapshot)
}
