package api

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/gpn/engine"
	"github.com/metacubex/mihomo/gpn/state"
)

// The interception surface. Reads are one snapshot; every write names the
// revision it was read at and changes exactly one thing.
//
// One-thing-per-write rather than a whole-document PUT, because these are not
// symmetric edits. Enabling an extension authorizes a capture set, a script
// set, a storage grant and possibly an unrestricted network grant; reordering
// changes which of two extensions owns an overlapping host. A single endpoint
// taking the whole document would make those indistinguishable from renaming
// something, and the confirmation an operator gave would not correspond to any
// particular decision.

var interception struct {
	engine *engine.Engine
}

// SetInterceptionEngine installs the engine the routes operate on. Passing nil
// withdraws it, which is what a failed document load must do: the routes then
// answer 503 with a reason rather than rendering an engine that is not there.
func SetInterceptionEngine(e *engine.Engine) {
	mu.Lock()
	defer mu.Unlock()
	interception.engine = e
}

func currentEngine() *engine.Engine {
	mu.RLock()
	defer mu.RUnlock()
	return interception.engine
}

func interceptionRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)
	r.Get("/", getInterception)
	r.Put("/settings", putInterceptionSettings)
	r.Put("/order", putInterceptionOrder)
	r.Post("/review", postReview)
	r.Post("/extensions", postInstall)
	r.Route("/extensions/{id}", func(r chi.Router) {
		r.Get("/", getExtension)
		r.Delete("/", deleteExtension)
		r.Get("/update", getUpdate)
		r.Post("/update", postUpdate)
		r.Put("/enabled", putExtensionEnabled)
		r.Put("/egress", putExtensionEgress)
		r.Put("/capture-dns", putExtensionCaptureDNS)
		r.Put("/settings/{key}", putExtensionSetting)
	})
	return r
}

// postReview fetches a candidate and reports what it is, without installing it.
//
// It takes no revision because it changes nothing. The digest it returns is
// what the install must quote back, and that is where the concurrency control
// lives -- reviewing something twice is free, installing something you did not
// review is not possible.
func postReview(w http.ResponseWriter, r *http.Request) {
	e := currentEngine()
	if e == nil {
		unavailable(w, r, "the interception engine is not installed")
		return
	}
	var body engine.ImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&body); err != nil {
		badRequest(w, r, "malformed request body: "+err.Error())
		return
	}
	ctx, cancel := contextWithTimeout(r, 2*time.Minute)
	defer cancel()

	candidate, err := e.Fetch(ctx, body)
	if err != nil {
		writeEngineError(w, r, err, e)
		return
	}
	render.JSON(w, r, render.M{"candidate": candidate, "revision": e.Revision()})
}

type installRequest struct {
	Revision string `json:"revision"`
	engine.InstallRequest
}

func (b *installRequest) revision() string { return b.Revision }

func postInstall(w http.ResponseWriter, r *http.Request) {
	var body installRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	ctx, cancel := contextWithTimeout(r, 2*time.Minute)
	defer cancel()

	snapshot, revision, err := e.Install(ctx, body.Revision, body.InstallRequest)
	respondEngine(w, r, snapshot, revision, err, e)
}

func getUpdate(w http.ResponseWriter, r *http.Request) {
	e := currentEngine()
	if e == nil {
		unavailable(w, r, "the interception engine is not installed")
		return
	}
	ctx, cancel := contextWithTimeout(r, 2*time.Minute)
	defer cancel()

	candidate, err := e.CheckUpdate(ctx, chi.URLParam(r, "id"))
	if err != nil {
		writeEngineError(w, r, err, e)
		return
	}
	render.JSON(w, r, render.M{"candidate": candidate, "revision": e.Revision()})
}

type updateRequest struct {
	Revision string `json:"revision"`
	Digest   string `json:"digest"`
}

func (b *updateRequest) revision() string { return b.Revision }

func postUpdate(w http.ResponseWriter, r *http.Request) {
	var body updateRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	ctx, cancel := contextWithTimeout(r, 2*time.Minute)
	defer cancel()

	snapshot, revision, err := e.ApplyUpdate(ctx, body.Revision, chi.URLParam(r, "id"), body.Digest)
	respondEngine(w, r, snapshot, revision, err, e)
}

// interceptionResponse is what every read and every successful write returns,
// so a client never has to follow a write with a read to know what it now has.
type interceptionResponse struct {
	Snapshot engine.Snapshot `json:"snapshot"`
	Revision string          `json:"revision"`
}

func getInterception(w http.ResponseWriter, r *http.Request) {
	e := currentEngine()
	if e == nil {
		unavailable(w, r, "the interception engine is not installed")
		return
	}
	snapshot, err := e.Snapshot()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, render.M{"message": err.Error()})
		return
	}
	render.JSON(w, r, interceptionResponse{Snapshot: snapshot, Revision: e.Revision()})
}

func getExtension(w http.ResponseWriter, r *http.Request) {
	e := currentEngine()
	if e == nil {
		unavailable(w, r, "the interception engine is not installed")
		return
	}
	detail, err := e.Detail(chi.URLParam(r, "id"))
	if err != nil {
		writeEngineError(w, r, err, e)
		return
	}
	render.JSON(w, r, render.M{"extension": detail, "revision": e.Revision()})
}

type settingsRequest struct {
	Revision               string `json:"revision"`
	Enabled                bool   `json:"enabled"`
	HTTP2                  bool   `json:"http2"`
	QUICFallbackProtection bool   `json:"quicFallbackProtection"`
}

func putInterceptionSettings(w http.ResponseWriter, r *http.Request) {
	var body settingsRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	snapshot, revision, err := e.SetSettings(body.Revision, engine.MITMSettings{
		Enabled:                body.Enabled,
		HTTP2:                  body.HTTP2,
		QUICFallbackProtection: body.QUICFallbackProtection,
	})
	respondEngine(w, r, snapshot, revision, err, e)
}

type orderRequest struct {
	Revision string   `json:"revision"`
	Order    []string `json:"order"`
}

func putInterceptionOrder(w http.ResponseWriter, r *http.Request) {
	var body orderRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	snapshot, revision, err := e.Reorder(body.Revision, body.Order)
	respondEngine(w, r, snapshot, revision, err, e)
}

type enabledRequest struct {
	Revision string `json:"revision"`
	Enabled  bool   `json:"enabled"`
}

func putExtensionEnabled(w http.ResponseWriter, r *http.Request) {
	var body enabledRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	snapshot, revision, err := e.SetEnabled(body.Revision, chi.URLParam(r, "id"), body.Enabled)
	respondEngine(w, r, snapshot, revision, err, e)
}

type egressRequest struct {
	Revision string `json:"revision"`
	Group    string `json:"group"`
}

func putExtensionEgress(w http.ResponseWriter, r *http.Request) {
	var body egressRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	snapshot, revision, err := e.SetEgressGroup(body.Revision, chi.URLParam(r, "id"), body.Group)
	respondEngine(w, r, snapshot, revision, err, e)
}

type captureDNSRequest struct {
	Revision string `json:"revision"`
	Resolver string `json:"resolver"`
}

func putExtensionCaptureDNS(w http.ResponseWriter, r *http.Request) {
	var body captureDNSRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	snapshot, revision, err := e.SetCaptureDNS(body.Revision, chi.URLParam(r, "id"), body.Resolver)
	respondEngine(w, r, snapshot, revision, err, e)
}

type settingValueRequest struct {
	Revision string          `json:"revision"`
	Value    json.RawMessage `json:"value"`
}

func putExtensionSetting(w http.ResponseWriter, r *http.Request) {
	var body settingValueRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	snapshot, revision, err := e.SetSettingValue(body.Revision, chi.URLParam(r, "id"), chi.URLParam(r, "key"), body.Value)
	respondEngine(w, r, snapshot, revision, err, e)
}

type deleteRequest struct {
	Revision string `json:"revision"`
}

func deleteExtension(w http.ResponseWriter, r *http.Request) {
	var body deleteRequest
	e, ok := decodeWrite(w, r, &body)
	if !ok {
		return
	}
	snapshot, revision, err := e.Uninstall(body.Revision, chi.URLParam(r, "id"))
	respondEngine(w, r, snapshot, revision, err, e)
}

// decodeWrite is the shared preamble for every write: the engine must be
// installed, the body must parse, and it must quote a revision. It returns
// ok=false having already written the response.
//
// The revision check lives here rather than in each handler because it is not a
// per-route nicety -- it is what stops two operators with this page open in two
// tabs from silently overwriting each other's decisions about what may decrypt
// traffic.
func decodeWrite(w http.ResponseWriter, r *http.Request, into revisioned) (*engine.Engine, bool) {
	e := currentEngine()
	if e == nil {
		unavailable(w, r, "the interception engine is not installed")
		return nil, false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(into); err != nil {
		badRequest(w, r, "malformed request body: "+err.Error())
		return nil, false
	}
	if into.revision() == "" {
		badRequest(w, r, "revision is required; read the current state first and quote what it returned")
		return nil, false
	}
	return e, true
}

// revisioned is every write body, which is every body: there is no unversioned
// write on this surface.
type revisioned interface{ revision() string }

func (b *settingsRequest) revision() string     { return b.Revision }
func (b *orderRequest) revision() string        { return b.Revision }
func (b *enabledRequest) revision() string      { return b.Revision }
func (b *egressRequest) revision() string       { return b.Revision }
func (b *captureDNSRequest) revision() string   { return b.Revision }
func (b *settingValueRequest) revision() string { return b.Revision }
func (b *deleteRequest) revision() string       { return b.Revision }

func respondEngine(w http.ResponseWriter, r *http.Request, snapshot engine.Snapshot, revision string, err error, e *engine.Engine) {
	if err != nil {
		writeEngineError(w, r, err, e)
		return
	}
	render.JSON(w, r, interceptionResponse{Snapshot: snapshot, Revision: revision})
}

// writeEngineError maps an engine failure onto a status a client can act on.
//
// A revision conflict carries the current revision, so a client can re-read,
// show the operator what changed, and retry -- rather than being told only that
// it lost.
func writeEngineError(w http.ResponseWriter, r *http.Request, err error, e *engine.Engine) {
	switch {
	case errors.Is(err, state.ErrRevisionConflict):
		render.Status(r, http.StatusConflict)
		render.JSON(w, r, render.M{
			"message":  "the interception document changed since you read it",
			"revision": e.Revision(),
		})
	case errors.Is(err, engine.ErrModuleNotFound):
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, render.M{"message": err.Error()})
	case errors.Is(err, engine.ErrInvalidRequest):
		badRequest(w, r, err.Error())
	default:
		// Anything else is the document refusing to validate or the write
		// failing. Both leave the running configuration untouched, so the
		// message is the whole of what the operator needs.
		render.Status(r, http.StatusUnprocessableEntity)
		render.JSON(w, r, render.M{"message": err.Error()})
	}
}
