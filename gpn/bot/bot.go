// Package bot is the Telegram control plane, in-process.
//
// It is deliberately much smaller than the bot it replaces. That one carried a
// complete extension marketplace inside a chat client: browse, review, install,
// bind settings, enable. All of it is gone, because zashboard owns extension
// management now and a second surface for authorizing what may decrypt traffic
// is not a convenience -- it is a second place for the operator's confirmation
// to mean something slightly different.
//
// What is left is what a chat client is actually good at: telling you something
// happened when you are not looking at a dashboard, and answering a question
// from a phone. So the bot reads and it alerts. It cannot enable an extension,
// install one, change policy, restart a service or touch the interception CA.
// The narrowness is the design: a token in a chat app is a credential that
// travels, and what it can do if it leaks is bounded here rather than by
// whoever holds it.
package bot

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/gpn/state"
	"github.com/metacubex/mihomo/log"
)

// documentVersion is the exact bot.json schema this build accepts.
const documentVersion = 1

// Document is the bot's own state, beside the resolver's and the engine's.
//
// A third document rather than a field on one of the other two, because it is
// neither: the resolver document is what the gateway answers with and the
// interception document is what may decrypt. Putting a chat credential in
// either would widen what a write to those means.
type Document struct {
	Version int  `json:"version"`
	Enabled bool `json:"enabled"`
	// Token is the Telegram bot token. The file is 0600 like every other
	// document, and no API read ever returns this field.
	Token string `json:"token"`
	// Admins is the complete set of Telegram user ids allowed to issue
	// commands. An empty set means nobody, which is what an enabled bot with no
	// admins has to mean: the alternative is a bot that answers everyone.
	Admins []int64 `json:"admins"`
	// Alerts turns transition notifications on. Off by default: a gateway that
	// starts messaging an operator they did not ask to be messaged is a
	// surprise, and the first thing they will do is turn it off.
	Alerts bool `json:"alerts"`
}

// DefaultDocument is a bot that is configured and doing nothing.
func DefaultDocument() Document {
	return Document{Version: documentVersion, Enabled: false, Admins: []int64{}, Alerts: false}
}

// View is what the API returns. It cannot carry the token: a client learns
// whether one is set, never what it is.
type View struct {
	Enabled  bool    `json:"enabled"`
	TokenSet bool    `json:"token_set"`
	Admins   []int64 `json:"admins"`
	Alerts   bool    `json:"alerts"`
	// State is what the poll loop is actually doing, which is not derivable
	// from the document: a bot can be enabled and configured and still be
	// failing to reach Telegram.
	State string `json:"state"`
	// LastError is the most recent failure, empty when there is none.
	LastError string `json:"last_error,omitempty"`
}

// Facts is everything the bot is allowed to know, supplied by the host.
//
// An interface of functions rather than a handle on the resolver and the
// engine, and that is the enforcement rather than a style choice: the bot
// package cannot import them, so no command can be added that does more than
// read what these return. Widening what the bot can do requires widening this
// struct, which is a visible change in the one file that wires it.
type Facts struct {
	// Status is the gateway's current state, or the zero value before the
	// subsystems exist.
	Status func() Status
	// Resolve explains what the resolver would decide for a name, without
	// resolving it.
	Resolve func(name string) (Explanation, error)
}

// Status is the gateway snapshot the bot renders.
type Status struct {
	ResolverUp     bool
	Queries        uint64
	Blocked        uint64
	CacheHits      uint64
	CacheMisses    uint64
	ChinaUpstreams []string
	TrustUpstreams []string
	Gateway        string

	InterceptionInstalled bool
	InterceptionEnabled   bool
	Extensions            int
	EnabledExtensions     int

	CertificateLoaded   bool
	CertificateNotAfter time.Time
	CertificateCovers   bool
	MissingHosts        []string

	Subscriptions []Subscription
}

// Subscription is one policy subscription's health.
type Subscription struct {
	Name  string
	OK    bool
	Error string
}

// Explanation is what the resolver would do with a name and why.
type Explanation struct {
	Name    string
	Verdict string
	Reason  string
	// Extension names the capture that owns this host, empty when none does.
	Extension string
}

// Dialer is how the bot reaches Telegram.
//
// Supplied by the host and pointed at the core's own inner dialer, so the
// connection obeys the operator's rules exactly as any other would. That is not
// symmetry for its own sake: api.telegram.org is unreachable from a good number
// of the networks this gateway is deployed on, and the operator has already
// configured how to reach such places. A private proxy knob would be a second,
// worse answer to a question their rules already answer.
type Dialer func(ctx context.Context, host string, port int) (net.Conn, error)

// Service owns the document, the poll loop and the alert monitor.
type Service struct {
	doc   *state.Doc[Document]
	facts Facts
	dial  Dialer

	mu        sync.Mutex
	cancel    context.CancelFunc
	running   bool
	state     string
	lastError string
	// stopped is closed by the run loop when it exits, so Apply can wait for
	// the previous generation to be gone before starting the next. Two loops
	// long-polling one token make Telegram hand each update to whichever asked
	// first, so commands would be answered at random.
	stopped chan struct{}
}

// Open loads the document at path, creating a disabled one if absent.
func Open(path string, facts Facts, dial Dialer) (*Service, error) {
	doc, err := state.New(path, DefaultDocument())
	if err != nil {
		return nil, err
	}
	s := &Service{doc: doc, facts: facts, dial: dial, state: "stopped"}
	if err := s.validate(doc.Get().Value); err != nil {
		return nil, fmt.Errorf("gpn/bot: %s is unusable: %w", path, err)
	}
	return s, nil
}

// Document returns the current document and its revision.
func (s *Service) Document() (Document, string) {
	snapshot := s.doc.Get()
	return snapshot.Value, snapshot.Revision
}

// View renders the document without its token, plus what the loop is doing.
func (s *Service) View() View {
	doc, _ := s.Document()
	s.mu.Lock()
	runState, lastErr := s.state, s.lastError
	s.mu.Unlock()
	return View{
		Enabled:   doc.Enabled,
		TokenSet:  strings.TrimSpace(doc.Token) != "",
		Admins:    append([]int64(nil), doc.Admins...),
		Alerts:    doc.Alerts,
		State:     runState,
		LastError: lastErr,
	}
}

// Update writes the document and restarts the loop to match it.
//
// An empty token in the request means "leave the stored one alone", which is
// what lets a console edit the admin list without ever having held the token.
// Clearing it is a separate, explicit act: send the sentinel below.
const ClearToken = "-"

// Update applies an operator write. token == "" keeps the stored token,
// token == ClearToken removes it.
func (s *Service) Update(revision string, next Document, token string) (View, string, error) {
	next.Version = documentVersion
	updated, err := s.doc.Update(revision, func(current Document) (Document, error) {
		switch strings.TrimSpace(token) {
		case "":
			next.Token = current.Token
		case ClearToken:
			next.Token = ""
		default:
			next.Token = strings.TrimSpace(token)
		}
		next.Admins = normaliseAdmins(next.Admins)
		if err := s.validate(next); err != nil {
			return current, err
		}
		return next, nil
	})
	if err != nil {
		return s.View(), updated.Revision, err
	}
	s.Apply()
	return s.View(), updated.Revision, nil
}

func (s *Service) validate(doc Document) error {
	if doc.Version != documentVersion {
		return fmt.Errorf("bot document version must be %d", documentVersion)
	}
	if len(doc.Admins) > 64 {
		return fmt.Errorf("at most 64 admins may be configured")
	}
	for _, id := range doc.Admins {
		if id == 0 {
			return fmt.Errorf("0 is not a Telegram user id")
		}
	}
	if doc.Enabled && strings.TrimSpace(doc.Token) == "" {
		return fmt.Errorf("a bot cannot be enabled without a token")
	}
	if doc.Enabled && len(doc.Admins) == 0 {
		// Not pedantry: an enabled bot with no admin set answers nobody, which
		// an operator will read as "the bot is broken" and go looking for a
		// network fault. Refusing says what is actually missing.
		return fmt.Errorf("a bot cannot be enabled without at least one admin id")
	}
	return nil
}

func normaliseAdmins(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Apply starts, stops or restarts the loop to match the document.
//
// Called after every write and once at startup. It always tears the previous
// generation down first and waits for it, because two loops long-polling one
// token make Telegram hand each update to whichever asked first.
func (s *Service) Apply() {
	doc, _ := s.Document()

	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	previous := s.stopped
	s.stopped = nil
	s.running = false
	s.mu.Unlock()

	if previous != nil {
		select {
		case <-previous:
		case <-time.After(pollTimeout + 5*time.Second):
			log.Warnln("[GPN/BOT] the previous poll loop did not stop in time")
		}
	}

	if !doc.Enabled || strings.TrimSpace(doc.Token) == "" {
		s.setState("stopped", "")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	s.mu.Lock()
	s.cancel, s.stopped, s.running = cancel, stopped, true
	s.mu.Unlock()

	go func() {
		defer close(stopped)
		s.run(ctx, doc)
	}()
}

// Shutdown stops the loop.
func (s *Service) Shutdown() {
	s.mu.Lock()
	cancel, stopped := s.cancel, s.stopped
	s.cancel, s.stopped, s.running = nil, nil, false
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		select {
		case <-stopped:
		case <-time.After(pollTimeout + 5*time.Second):
		}
	}
	s.setState("stopped", "")
}

func (s *Service) setState(runState, lastError string) {
	s.mu.Lock()
	s.state, s.lastError = runState, lastError
	s.mu.Unlock()
}

// Running reports whether a poll loop is live, for tests and the view.
func (s *Service) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
