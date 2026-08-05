// Package api serves 5gpn's control surface on mihomo's existing controller.
//
// There is no second listener, no second credential and no second origin. The
// routes register through hub/route.Register, which mounts them inside the
// group that already applies authentication(secret) -- so a client that can
// talk to /configs can talk to these, and one that cannot, cannot. That is the
// whole auth design. The 5gpn bearer token, the one-use log tickets, the
// zashboard handoff and the 127.0.0.1/127.0.0.2 origin split are gone.
package api

import (
	"sync"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/hub/route"
)

// ControllerAPI is the version of the surface as a whole. It changes only when
// the shape of capability discovery itself changes, not when a feature does --
// features carry their own versions.
const ControllerAPI = "1"

// Feature is what /capabilities advertises about one subsystem.
type Feature struct {
	// Version is the schema version of this feature's payloads. A client that
	// does not understand exactly this number must treat the feature as absent
	// rather than render it: field meanings may have moved, and showing an
	// operator a status that might be wrong is worse than showing nothing.
	Version int `json:"version"`
	// Owner is set by features whose paths are owner-scoped.
	Owner string `json:"owner,omitempty"`
}

var (
	mu       sync.RWMutex
	features = map[string]Feature{}
)

// Advertise publishes a feature, or with a zero Version withdraws it.
//
// Subsystems call this as they come up, so /capabilities reports what is
// actually installed rather than what this build could in principle do. A
// gateway whose interception document failed to load must not advertise
// interception -- the client would render a panel over an engine that is not
// there.
func Advertise(name string, f Feature) {
	mu.Lock()
	defer mu.Unlock()
	if f.Version == 0 {
		delete(features, name)
		return
	}
	features[name] = f
}

func snapshot() map[string]Feature {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]Feature, len(features))
	for k, v := range features {
		out[k] = v
	}
	return out
}

type capabilitiesResponse struct {
	ControllerAPI string             `json:"controllerApi"`
	Features      map[string]Feature `json:"features"`
}

// noStore marks discovery responses uncacheable. They describe what the process
// is serving right now; a cached one describes what it was serving.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func registerControllerRoutes(r chi.Router) {
	r.Mount("/5gpn/interception", interceptionRouter())
	r.Mount("/5gpn/dns", dnsRouter())
	r.Mount("/5gpn/bot", botRouter())
	r.With(noStore).Get("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, capabilitiesResponse{
			ControllerAPI: ControllerAPI,
			Features:      snapshot(),
		})
	})
}

func init() {
	route.Register(registerControllerRoutes)
}
