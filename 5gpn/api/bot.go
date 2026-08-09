package api

import (
	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/5gpn/bot"
	"github.com/metacubex/mihomo/5gpn/state"
)

// The bot surface: one read and one write.
//
// Whole-document rather than a write per field, unlike /5gpn/interception. The
// reason those are separate is that each authorizes something different --
// enabling an extension is not renaming one. Here there is a single decision:
// who may ask this gateway questions over Telegram, and whether it is on. The
// token, the admin set and the switch are one answer to that, and splitting
// them would let a gateway sit in a state nobody chose, with a token and no
// admins or admins and no token.

var botService struct {
	service *bot.Service
}

// SetBotService installs the bot the routes operate on. Passing nil withdraws
// it, which is what a failed document load does.
func SetBotService(s *bot.Service) {
	mu.Lock()
	defer mu.Unlock()
	botService.service = s
}

func currentBot() *bot.Service {
	mu.RLock()
	defer mu.RUnlock()
	return botService.service
}

func botRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)
	r.Get("/", getBot)
	r.Put("/", putBot)
	return r
}

func getBot(w http.ResponseWriter, r *http.Request) {
	s := currentBot()
	if s == nil {
		unavailable(w, r, "the Telegram bot is not installed")
		return
	}
	view, revision := s.Snapshot()
	render.JSON(w, r, render.M{"bot": view, "revision": revision})
}

type botRequest struct {
	Revision string  `json:"revision"`
	Enabled  bool    `json:"enabled"`
	Admins   []int64 `json:"admins"`
	Alerts   bool    `json:"alerts"`
	// Token is write-only and tri-state. Absent or empty keeps the stored
	// token, so a console that has never seen it can still edit the admin list;
	// "-" clears it. There is no value of this field that reads the token back.
	Token string `json:"token,omitempty"`
}

func (b *botRequest) revision() string { return b.Revision }

func putBot(w http.ResponseWriter, r *http.Request) {
	s := currentBot()
	if s == nil {
		unavailable(w, r, "the Telegram bot is not installed")
		return
	}
	var body botRequest
	if err := decodeRequestJSON(r, 64<<10, &body); err != nil {
		badRequest(w, r, "malformed request body: "+err.Error())
		return
	}
	if body.Revision == "" {
		badRequest(w, r, "revision is required; read the current state first and quote what it returned")
		return
	}

	view, revision, err := s.Update(body.Revision, bot.Document{
		Enabled: body.Enabled,
		Admins:  body.Admins,
		Alerts:  body.Alerts,
	}, body.Token)
	if err != nil {
		if err == state.ErrRevisionConflict {
			render.Status(r, http.StatusConflict)
			render.JSON(w, r, render.M{"message": "the bot document changed since you read it", "revision": revision})
			return
		}
		render.Status(r, http.StatusUnprocessableEntity)
		render.JSON(w, r, render.M{"message": err.Error()})
		return
	}
	render.JSON(w, r, render.M{"bot": view, "revision": revision})
}
