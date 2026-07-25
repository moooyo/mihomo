package route

import (
	"context"

	"github.com/metacubex/mihomo/component/overlay"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func contextBackground() context.Context { return context.Background() }

// noStore marks every overlay response uncacheable. These responses carry the
// live generation and the fencing identity; a cached one is a stale one, and a
// stale one is exactly what the processor must never act on.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// overlayControlRouter is the coordinator-facing read-write API.
func overlayControlRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)

	r.Get("/capabilities", getOverlayCapabilities)
	r.Route("/runtime-overlays/{owner}", func(r chi.Router) {
		r.Get("/", getOverlayReadback)
		r.Delete("/", purgeOverlay)
		r.Route("/generations/{id}", func(r chi.Router) {
			r.Put("/", stageGeneration)
			r.Post("/commit", commitGeneration)
			r.Post("/abort", abortGeneration)
		})
		r.Post("/readiness", registerProcessorReadiness)
	})
	return r
}

// overlayGenerationRouter is the processor-facing read-only API.
//
// It exposes exactly one method on exactly one path. No wildcard mounts, no
// mutating verbs: "read-only" here means no method on it may change overlay,
// lease or generation state, including as a side effect.
func overlayGenerationRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)
	r.Get("/runtime-overlays/{owner}/active", getActiveGeneration)
	return r
}

// capabilitiesResponse lets a client discover what this core supports without
// inferring it from a version string.
type capabilitiesResponse struct {
	ControllerAPI string                  `json:"controllerApi"`
	Features      map[string]featureDescr `json:"features"`
}

type featureDescr struct {
	Version int    `json:"version"`
	Owner   string `json:"owner,omitempty"`
}

func getOverlayCapabilities(w http.ResponseWriter, r *http.Request) {
	resp := capabilitiesResponse{
		ControllerAPI: "1",
		Features:      map[string]featureDescr{},
	}
	if m := tunnel.OverlayManager(); m != nil {
		resp.Features["runtime-overlays"] = featureDescr{Version: overlay.SchemaVersion, Owner: m.Owner()}
	}
	render.JSON(w, r, resp)
}

// managerFor resolves the overlay for the owner in the URL, writing the error
// response itself when it cannot.
func managerFor(w http.ResponseWriter, r *http.Request) *overlay.Manager {
	m := tunnel.OverlayManager()
	if m == nil {
		writeOverlayError(w, r, overlay.ErrDisabled)
		return nil
	}
	if owner := chi.URLParam(r, "owner"); owner != m.Owner() {
		writeOverlayError(w, r, overlay.ErrNotFound)
		return nil
	}
	return m
}

func getOverlayReadback(w http.ResponseWriter, r *http.Request) {
	m := managerFor(w, r)
	if m == nil {
		return
	}
	render.JSON(w, r, m.Readback())
}

func stageGeneration(w http.ResponseWriter, r *http.Request) {
	m := managerFor(w, r)
	if m == nil {
		return
	}
	doc := &overlay.Document{}
	if err := render.DecodeJSON(r.Body, doc); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if id := chi.URLParam(r, "id"); doc.GenerationID != "" && doc.GenerationID != id {
		writeOverlayError(w, r, overlay.ErrInvalidDocument)
		return
	} else if doc.GenerationID == "" {
		doc.GenerationID = id
	}

	// Staging validates against the live configuration, so it runs under the
	// same lock as a config apply. Otherwise a generation could be validated
	// against one configuration and committed against another.
	compiled, err := executor.WithApplyLock(func() (*overlay.Compiled, error) {
		return m.Stage(doc)
	})
	if err != nil {
		writeOverlayError(w, r, err)
		return
	}
	render.JSON(w, r, map[string]any{
		"generationId": compiled.Document.GenerationID,
		"digests":      compiled.Digests,
		"clientRules":  compiled.Client.Len(),
		"capabilities": len(compiled.Document.Egress.Capabilities),
		"coreRevision": executor.CoreRevision(),
	})
}

type commitRequestBody struct {
	ExpectedActive       string `json:"expectedActiveGeneration"`
	ExpectedCoreRevision uint64 `json:"expectedCoreConfigRevision"`
}

func commitGeneration(w http.ResponseWriter, r *http.Request) {
	m := managerFor(w, r)
	if m == nil {
		return
	}
	body := &commitRequestBody{}
	if r.ContentLength > 0 {
		if err := render.DecodeJSON(r.Body, body); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
	}

	result, err := executor.WithApplyLock(func() (*overlay.CommitResult, error) {
		return m.Commit(overlay.CommitRequest{
			GenerationID:         chi.URLParam(r, "id"),
			ExpectedActive:       body.ExpectedActive,
			ExpectedCoreRevision: body.ExpectedCoreRevision,
		})
	})
	if err != nil {
		writeOverlayError(w, r, err)
		return
	}
	render.JSON(w, r, result)
}

func abortGeneration(w http.ResponseWriter, r *http.Request) {
	m := managerFor(w, r)
	if m == nil {
		return
	}
	if err := m.Abort(chi.URLParam(r, "id")); err != nil {
		writeOverlayError(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func purgeOverlay(w http.ResponseWriter, r *http.Request) {
	m := managerFor(w, r)
	if m == nil {
		return
	}
	if _, err := executor.WithApplyLock(func() (struct{}, error) {
		return struct{}{}, m.Purge()
	}); err != nil {
		writeOverlayError(w, r, err)
		return
	}
	log.Warnln("[Overlay] durable state purged through the control socket")
	render.NoContent(w, r)
}

type readinessBody struct {
	ProcessorID     string `json:"processorId"`
	ProcessInstance string `json:"processInstanceId"`
	GenerationID    string `json:"generationId"`
	BundleDigest    string `json:"sidecarBundleDigest"`
	CertHostSet     string `json:"certificateHostSetDigest"`
}

func registerProcessorReadiness(w http.ResponseWriter, r *http.Request) {
	m := managerFor(w, r)
	if m == nil {
		return
	}
	body := &readinessBody{}
	if err := render.DecodeJSON(r.Body, body); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	uid, gid := peerFromContext(r.Context())
	lease, err := m.RegisterReadiness(body.ProcessorID, body.ProcessInstance, body.GenerationID,
		body.BundleDigest, body.CertHostSet, uid, gid)
	if err != nil {
		writeOverlayError(w, r, err)
		return
	}
	render.JSON(w, r, lease)
}

func getActiveGeneration(w http.ResponseWriter, r *http.Request) {
	m := tunnel.OverlayManager()
	if m == nil {
		writeOverlayError(w, r, overlay.ErrDisabled)
		return
	}
	if owner := chi.URLParam(r, "owner"); owner != m.Owner() {
		writeOverlayError(w, r, overlay.ErrNotFound)
		return
	}
	render.JSON(w, r, m.Snapshot().View())
}

// overlayErrorBody is the stable machine-readable error shape. The code is what
// a coordinator branches on; the message is for humans reading logs.
type overlayErrorBody struct {
	Code      overlay.Code `json:"code"`
	Message   string       `json:"message"`
	Retryable bool         `json:"retryable"`
}

func writeOverlayError(w http.ResponseWriter, r *http.Request, err error) {
	code := overlay.CodeOf(err)
	render.Status(r, overlayHTTPStatus(code))
	render.JSON(w, r, overlayErrorBody{Code: code, Message: err.Error(), Retryable: code.Retryable()})
}

func overlayHTTPStatus(code overlay.Code) int {
	switch code {
	case overlay.CodeInvalidDocument, overlay.CodeQuotaExceeded, overlay.CodeUnsupportedSchema:
		return http.StatusBadRequest
	case overlay.CodeNotFound, overlay.CodeDisabled:
		return http.StatusNotFound
	case overlay.CodeCASConflict, overlay.CodeWrongState, overlay.CodeModeConflict, overlay.CodeAnchorInvalid:
		return http.StatusConflict
	case overlay.CodeDependencyMissing, overlay.CodeNotReady:
		return http.StatusFailedDependency
	case overlay.CodeStoreCorrupt:
		return http.StatusInternalServerError
	}
	return http.StatusInternalServerError
}
