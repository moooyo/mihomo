package api

import (
	"errors"
	"strconv"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/5gpn/dns"
	"github.com/metacubex/mihomo/5gpn/state"
)

// The DNS surface is one document, read whole and written whole.
//
// Field-level endpoints were the previous design -- a route for the policy, one
// for the upstreams, one for the client subnet -- and they made every
// cross-cutting edit a sequence of writes with no way to name the sequence.
// Listen and Gateway remain in the document as installation-owned runtime
// coordinates; whole-document clients must round-trip them unchanged.

var dnsService struct {
	svc *dns.Service
}

// SetDNSService installs the resolver the routes operate on.
func SetDNSService(svc *dns.Service) {
	mu.Lock()
	defer mu.Unlock()
	dnsService.svc = svc
}

func currentDNS() *dns.Service {
	mu.RLock()
	defer mu.RUnlock()
	return dnsService.svc
}

func dnsRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)
	r.Get("/", getDNS)
	r.Put("/", putDNS)
	r.Get("/stats", getDNSStats)
	r.Get("/querylog", getQueryLog)
	r.Get("/resolve", getResolve)
	r.Post("/flush", postFlush)
	return r
}

// dnsResponse is the whole read: the document, the revision a write must quote,
// and the live state that document produced.
type dnsResponse struct {
	Document      dns.Document             `json:"document"`
	Revision      string                   `json:"revision"`
	Stats         dns.Stats                `json:"stats"`
	Subscriptions []dns.SubscriptionStatus `json:"subscriptions"`
}

func getDNS(w http.ResponseWriter, r *http.Request) {
	svc := currentDNS()
	if svc == nil {
		unavailable(w, r, "the DNS engine is not installed")
		return
	}
	doc, revision := svc.Document()
	render.JSON(w, r, dnsResponse{
		Document:      doc,
		Revision:      revision,
		Stats:         svc.Resolver().Stats(),
		Subscriptions: svc.Subscriptions(),
	})
}

// dnsWriteRequest carries the document and the revision it was read at.
//
// The revision is required rather than optional. Two operators with this page
// open in two tabs is the ordinary case, not the exotic one, and last-write-
// wins on a document containing the block list is a policy change nobody made
// and nobody sees.
type dnsWriteRequest struct {
	Revision string       `json:"revision"`
	Document dns.Document `json:"document"`
}

func putDNS(w http.ResponseWriter, r *http.Request) {
	svc := currentDNS()
	if svc == nil {
		unavailable(w, r, "the DNS engine is not installed")
		return
	}
	var body dnsWriteRequest
	if err := decodeRequestJSON(r, 4<<20, &body); err != nil {
		badRequest(w, r, "malformed request body: "+err.Error())
		return
	}
	if body.Revision == "" {
		badRequest(w, r, "revision is required; read the document first and quote what it returned")
		return
	}

	doc, revision, err := svc.Update(body.Revision, func(dns.Document) (dns.Document, error) {
		return body.Document, nil
	})
	switch {
	case errors.Is(err, state.ErrRevisionConflict):
		render.Status(r, http.StatusConflict)
		render.JSON(w, r, render.M{
			"message":  "the document changed since you read it",
			"revision": revision,
		})
		return
	case errors.Is(err, dns.ErrInvalidPolicy), errors.Is(err, dns.ErrInvalidUpstream):
		badRequest(w, r, err.Error())
		return
	case err != nil:
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, render.M{"message": err.Error()})
		return
	}

	render.JSON(w, r, dnsResponse{
		Document:      doc,
		Revision:      revision,
		Stats:         svc.Resolver().Stats(),
		Subscriptions: svc.Subscriptions(),
	})
}

func getDNSStats(w http.ResponseWriter, r *http.Request) {
	svc := currentDNS()
	if svc == nil {
		unavailable(w, r, "the DNS engine is not installed")
		return
	}
	render.JSON(w, r, svc.Resolver().Stats())
}

func getQueryLog(w http.ResponseWriter, r *http.Request) {
	svc := currentDNS()
	if svc == nil {
		unavailable(w, r, "the DNS engine is not installed")
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = min(n, 2000)
		}
	}
	render.JSON(w, r, render.M{
		"entries": svc.Resolver().QueryLog(r.URL.Query().Get("q"), limit),
	})
}

func getResolve(w http.ResponseWriter, r *http.Request) {
	svc := currentDNS()
	if svc == nil {
		unavailable(w, r, "the DNS engine is not installed")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		badRequest(w, r, "name is required")
		return
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	render.JSON(w, r, svc.Resolver().Explain(ctx, name))
}

func postFlush(w http.ResponseWriter, r *http.Request) {
	svc := currentDNS()
	if svc == nil {
		unavailable(w, r, "the DNS engine is not installed")
		return
	}
	svc.Resolver().FlushCache()
	render.NoContent(w, r)
}
