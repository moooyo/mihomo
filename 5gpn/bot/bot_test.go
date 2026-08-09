package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A stand-in Telegram, so the poll loop, the admin gate and the offset are
// exercised as they run rather than as they read.

type sentMessage struct {
	ChatID int64  `json:"chat_id"`
	Text   string `json:"text"`
}

type fakeTelegram struct {
	server *httptest.Server

	mu      sync.Mutex
	pending []update
	sent    []sentMessage
	offsets []int64
	polled  chan struct{}
}

func newFakeTelegram(t *testing.T) *fakeTelegram {
	t.Helper()
	f := &fakeTelegram{polled: make(chan struct{}, 64)}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "getMe":
			fmt.Fprint(w, `{"ok":true,"result":{"id":1,"username":"gateway_bot"}}`)
		case "getUpdates":
			var request struct {
				Offset int64 `json:"offset"`
			}
			_ = json.Unmarshal(body, &request)
			f.mu.Lock()
			f.offsets = append(f.offsets, request.Offset)
			out := f.pending
			f.pending = nil
			f.mu.Unlock()
			select {
			case f.polled <- struct{}{}:
			default:
			}
			raw, _ := json.Marshal(out)
			fmt.Fprintf(w, `{"ok":true,"result":%s}`, raw)
		case "sendMessage":
			var message sentMessage
			_ = json.Unmarshal(body, &message)
			f.mu.Lock()
			f.sent = append(f.sent, message)
			f.mu.Unlock()
			fmt.Fprint(w, `{"ok":true,"result":{}}`)
		default:
			fmt.Fprint(w, `{"ok":false,"description":"unknown method"}`)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeTelegram) queue(updates ...update) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, updates...)
}

func (f *fakeTelegram) messages() []sentMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMessage(nil), f.sent...)
}

func (f *fakeTelegram) lastOffset() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.offsets) == 0 {
		return -1
	}
	return f.offsets[len(f.offsets)-1]
}

func commandUpdate(updateID, fromID, chatID int64, text string) update {
	u := update{UpdateID: updateID}
	u.Message = new(struct {
		MessageID int64 `json:"message_id"`
		From      *struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"from"`
		Chat *struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
		Text string `json:"text"`
	})
	u.Message.MessageID = updateID
	u.Message.Text = text
	u.Message.From = new(struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	})
	u.Message.From.ID = fromID
	u.Message.Chat = new(struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	})
	u.Message.Chat.ID = chatID
	u.Message.Chat.Type = "private"
	return u
}

// runAgainst drives the loop by hand, so a test does not wait on the poll
// interval or race the supervisor.
func runAgainst(t *testing.T, f *fakeTelegram, doc Document, facts Facts) (*Service, *client) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bot.json"), facts, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(doc.Token, nil)
	c.base = f.server.URL
	return s, c
}

func admins(ids ...int64) map[int64]struct{} {
	out := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func TestOnlyAdminsAreAnsweredAndAStrangerGetsSilence(t *testing.T) {
	f := newFakeTelegram(t)
	s, c := runAgainst(t, f, Document{Token: "t"}, Facts{Status: func() Status { return Status{ResolverUp: true} }})

	set := admins(42)
	s.handle(context.Background(), c, set, commandUpdate(1, 42, 42, "/status"))
	s.handle(context.Background(), c, set, commandUpdate(2, 99, 99, "/status"))

	sent := f.messages()
	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want only the admin's answer: %+v", len(sent), sent)
	}
	if sent[0].ChatID != 42 {
		t.Errorf("answered chat %d", sent[0].ChatID)
	}
}

// /id is the one command a stranger gets an answer to, because it is how an
// operator learns the number to put in the admin list -- and it discloses only
// the caller's own id, back to the caller.
func TestIDAnswersAnyoneBecauseItIsHowAnAdminIsConfigured(t *testing.T) {
	f := newFakeTelegram(t)
	s, c := runAgainst(t, f, Document{Token: "t"}, Facts{})

	s.handle(context.Background(), c, admins(42), commandUpdate(1, 99, 99, "/id"))

	sent := f.messages()
	if len(sent) != 1 || !strings.Contains(sent[0].Text, "99") {
		t.Fatalf("/id did not report the caller's own id: %+v", sent)
	}
	if strings.Contains(sent[0].Text, "42") {
		t.Error("/id disclosed a configured admin id to a stranger")
	}
}

// Nothing the bot answers may change anything. The command surface is the whole
// of the enforcement, so a command that is not in it must be refused rather
// than reaching a default that does something.
func TestNoCommandMutatesAnything(t *testing.T) {
	f := newFakeTelegram(t)
	s, c := runAgainst(t, f, Document{Token: "t"}, Facts{Status: func() Status { return Status{} }})

	tried := []string{"/enable", "/install https://example.com/x.yaml", "/restart", "/renew"}
	for _, command := range tried {
		s.handle(context.Background(), c, admins(42), commandUpdate(1, 42, 42, command))
	}
	sent := f.messages()
	if len(sent) != len(tried) {
		t.Fatalf("sent %d answers for %d commands", len(sent), len(tried))
	}
	for i, message := range sent {
		if !strings.HasPrefix(message.Text, "unknown command.") {
			t.Errorf("%q was answered with something other than a refusal: %q", tried[i], message.Text)
		}
	}
}

// Telegram replays everything at or above the offset, so an update the bot
// declines to act on has to advance it too -- otherwise a stranger's message
// is redelivered forever and the bot never sees anything newer.
func TestTheOffsetAdvancesPastUpdatesTheBotDeclines(t *testing.T) {
	f := newFakeTelegram(t)
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bot.json"), Facts{Status: func() Status { return Status{} }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A stranger's command and a photo, neither of which is answered.
	f.queue(commandUpdate(7, 99, 99, "/status"), update{UpdateID: 8})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doc := Document{Version: documentVersion, Enabled: true, Token: "t", Admins: []int64{42}}
	c := newClient(doc.Token, nil)
	c.base = f.server.URL

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runWithClient(ctx, doc, c, 0)
	}()

	// Two polls: the first delivers, the second must ask past both updates.
	<-f.polled
	<-f.polled
	cancel()
	<-done

	if got := f.lastOffset(); got != 9 {
		t.Errorf("the loop asked from offset %d, want 9 so neither update is replayed", got)
	}
	if sent := f.messages(); len(sent) != 0 {
		t.Errorf("a stranger's command was answered: %+v", sent)
	}
}

func TestStatusRendersWhatTheGatewayReports(t *testing.T) {
	f := newFakeTelegram(t)
	s, c := runAgainst(t, f, Document{Token: "t"}, Facts{Status: func() Status {
		return Status{
			ResolverUp: true, Queries: 1200, Blocked: 34, CacheHits: 900, CacheMisses: 300,
			Gateway: "10.0.1.20", ChinaUpstreams: []string{"a"}, TrustUpstreams: []string{"b", "c"},
			InterceptionInstalled: true, InterceptionEnabled: true,
			Extensions: 3, EnabledExtensions: 2,
			CertificateLoaded: true, CertificateCovers: false, MissingHosts: []string{"shop.example.com"},
			Subscriptions: []Subscription{{Name: "cn", OK: true}, {Name: "ads", OK: false, Error: "timeout"}},
		}
	}})

	s.handle(context.Background(), c, admins(42), commandUpdate(1, 42, 42, "/status"))
	sent := f.messages()
	if len(sent) != 1 {
		t.Fatalf("sent %d messages", len(sent))
	}
	text := sent[0].Text
	for _, want := range []string{"10.0.1.20", "1200", "34", "2 of 3", "DOES NOT COVER shop.example.com", "1 of 2 failing"} {
		if !strings.Contains(text, want) {
			t.Errorf("status omits %q:\n%s", want, text)
		}
	}
}

func TestResolveRefusesSomethingThatIsNotADomain(t *testing.T) {
	f := newFakeTelegram(t)
	called := false
	s, c := runAgainst(t, f, Document{Token: "t"}, Facts{
		Resolve: func(string) (Explanation, error) { called = true; return Explanation{}, nil },
	})

	s.handle(context.Background(), c, admins(42), commandUpdate(1, 42, 42, "/resolve not a domain"))
	if called {
		t.Error("a malformed name reached the resolver")
	}
	if sent := f.messages(); len(sent) != 1 || !strings.Contains(sent[0].Text, "not a valid domain") {
		t.Errorf("unexpected answer: %+v", f.messages())
	}
}

// An enabled bot with no admins answers nobody, which an operator reads as a
// broken bot and goes looking for a network fault. Refusing the write says what
// is actually missing.
func TestABotCannotBeEnabledWithoutATokenOrAnAdmin(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bot.json"), Facts{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, revision := s.Document()

	if _, _, err := s.Update(revision, Document{Enabled: true, Admins: []int64{42}}, ""); err == nil {
		t.Error("a bot was enabled with no token")
	}
	if _, _, err := s.Update(revision, Document{Enabled: true}, "secret"); err == nil {
		t.Error("a bot was enabled with no admins")
	}
	if _, _, err := s.Update(revision, Document{Enabled: true, Admins: []int64{42}}, "secret"); err != nil {
		t.Errorf("a complete configuration was refused: %v", err)
	}
}

// The console edits the admin list without ever having held the token, so an
// absent token in a write must keep the stored one rather than clear it.
func TestAWriteWithoutATokenKeepsTheStoredOne(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bot.json"), Facts{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, revision := s.Document()
	view, revision, err := s.Update(revision, Document{Enabled: true, Admins: []int64{42}}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !view.TokenSet {
		t.Fatal("the token was not stored")
	}

	view, revision, err = s.Update(revision, Document{Enabled: true, Admins: []int64{42, 43}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !view.TokenSet {
		t.Error("editing the admin list cleared the token")
	}
	doc, _ := s.Document()
	if doc.Token != "secret" {
		t.Errorf("stored token is now %q", doc.Token)
	}

	// Clearing has to be possible, and explicit.
	if _, _, err := s.Update(revision, Document{Enabled: false, Admins: []int64{42}}, ClearToken); err != nil {
		t.Fatal(err)
	}
	if doc, _ := s.Document(); doc.Token != "" {
		t.Error("the sentinel did not clear the token")
	}
}

// The token is a credential that must never be read back, whatever a client
// asks for.
func TestTheViewNeverCarriesTheToken(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bot.json"), Facts{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, revision := s.Document()
	if _, _, err := s.Update(revision, Document{Enabled: true, Admins: []int64{42}}, "super-secret-token"); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s.View())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret-token") {
		t.Fatalf("the view carries the token: %s", raw)
	}
}

// A transport error carries the request URL, which carries the token.
func TestAnErrorNeverCarriesTheToken(t *testing.T) {
	message := redactToken(`Post "https://api.telegram.org/bot123:ABC/getUpdates": dial tcp: timeout`, "123:ABC")
	if strings.Contains(message, "123:ABC") {
		t.Fatalf("the token survived redaction: %s", message)
	}
}

func TestApplyStopsThePreviousLoopBeforeStartingTheNext(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bot.json"), Facts{Status: func() Status { return Status{} }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, revision := s.Document()
	// Enabling starts a loop that will fail to reach the real Telegram, which
	// is fine: what is under test is the supervisor, not the transport.
	if _, _, err := s.Update(revision, Document{Enabled: true, Admins: []int64{42}}, "t"); err != nil {
		t.Fatal(err)
	}
	if !s.Running() {
		t.Fatal("enabling did not start a loop")
	}
	s.Shutdown()
	if s.Running() {
		t.Error("Shutdown left a loop running")
	}
	// Deadline only: Shutdown must not block on the poll it interrupted.
	done := make(chan struct{})
	go func() { defer close(done); s.Shutdown() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a second Shutdown blocked")
	}
}

func TestConcurrentUpdatesCannotReviveAnOlderLoop(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bot.json"), Facts{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	var loopMu sync.Mutex
	active, maximum := 0, 0
	started := make(chan string, 8)
	firstCancelled := make(chan struct{})
	releaseFirst := make(chan struct{})
	s.loop = func(ctx context.Context, doc Document, generation uint64) {
		loopMu.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		loopMu.Unlock()
		started <- doc.Token

		<-ctx.Done()
		if doc.Token == "one" {
			close(firstCancelled)
			<-releaseFirst
			// A cancelled generation must not overwrite the state of the
			// generation that superseded it, even if its teardown finishes late.
			s.setState(generation, "unreachable", "obsolete token")
		}
		loopMu.Lock()
		active--
		loopMu.Unlock()
	}

	_, revision := s.Document()
	_, revision, err = s.Update(revision, Document{Enabled: true, Admins: []int64{1}}, "one")
	if err != nil {
		t.Fatal(err)
	}
	if token := <-started; token != "one" {
		t.Fatalf("first loop token %q, want one", token)
	}

	type result struct {
		revision string
		err      error
	}
	secondDone := make(chan result, 1)
	go func() {
		_, nextRevision, updateErr := s.Update(revision, Document{Enabled: true, Admins: []int64{2}}, "two")
		secondDone <- result{revision: nextRevision, err: updateErr}
	}()
	<-firstCancelled

	current, secondRevision := s.Document()
	if current.Token != "two" {
		t.Fatalf("durable second token %q, want two", current.Token)
	}
	thirdEntered := make(chan struct{})
	thirdDone := make(chan result, 1)
	go func() {
		close(thirdEntered)
		_, nextRevision, updateErr := s.Update(secondRevision, Document{Enabled: true, Admins: []int64{3}}, "three")
		thirdDone <- result{revision: nextRevision, err: updateErr}
	}()
	<-thirdEntered

	// The third writer cannot publish while the second transition is still
	// waiting for generation one to exit.
	time.Sleep(50 * time.Millisecond)
	if current, _ := s.Document(); current.Token != "two" {
		t.Fatalf("third write overtook the in-progress transition: token %q", current.Token)
	}
	select {
	case result := <-thirdDone:
		t.Fatalf("third update returned before the prior generation stopped: %v", result.err)
	default:
	}

	close(releaseFirst)
	second := <-secondDone
	if second.err != nil {
		t.Fatalf("second update failed: %v", second.err)
	}
	third := <-thirdDone
	if third.err != nil {
		t.Fatalf("third update failed: %v", third.err)
	}

	for i, want := range []string{"two", "three"} {
		select {
		case token := <-started:
			if token != want {
				t.Fatalf("replacement loop %d token %q, want %q", i, token, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("replacement loop %d did not start", i)
		}
	}
	loopMu.Lock()
	gotMaximum := maximum
	loopMu.Unlock()
	if gotMaximum != 1 {
		t.Fatalf("observed %d simultaneous poll loops, want exactly one", gotMaximum)
	}

	view, snapshotRevision := s.Snapshot()
	if snapshotRevision != third.revision || len(view.Admins) != 1 || view.Admins[0] != 3 {
		t.Fatalf("view/revision are not the committed third snapshot: view=%+v revision=%q want=%q", view, snapshotRevision, third.revision)
	}
	if view.LastError == "obsolete token" {
		t.Fatal("a stale generation overwrote the current runtime state")
	}
	s.Shutdown()
}
