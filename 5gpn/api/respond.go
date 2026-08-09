package api

import (
	"context"
	"time"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/5gpn/state"
)

// Small shared response shapes, so every route says the same thing the same way
// and a client can key on one field.

func badRequest(w http.ResponseWriter, r *http.Request, message string) {
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, render.M{"message": message})
}

// decodeRequestJSON gives every controller write the same bounded, strict JSON
// semantics as a durable state document: one UTF-8 value, no duplicate or
// unknown fields, and no trailing payload.
func decodeRequestJSON(r *http.Request, maxBytes int64, dst any) error {
	return state.DecodeJSON(r.Body, maxBytes, dst)
}

// unavailable is for a subsystem that is not installed, which is deliberately
// distinct from one that is installed and switched off. Off is a document that
// loaded and says so; this is a document that did not load, and rendering it as
// off would tell an operator their configuration is being honoured when it is
// not being read.
func unavailable(w http.ResponseWriter, r *http.Request, message string) {
	render.Status(r, http.StatusServiceUnavailable)
	render.JSON(w, r, render.M{"message": message})
}

// contextWithTimeout bounds a handler that reaches the network, and inherits
// the request's cancellation so a client that goes away stops the work it
// started.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
