package bot

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// The poll loop and what it will answer.

const (
	// Backoff between failed polls. Telegram is frequently unreachable from the
	// networks this runs on, and a tight retry there is a request per
	// millisecond against a host that is refusing them.
	pollRetryMin = 5 * time.Second
	pollRetryMax = 5 * time.Minute
)

func (s *Service) run(ctx context.Context, doc Document, generation uint64) {
	s.runWithClient(ctx, doc, newClient(doc.Token, s.dial), generation)
}

// runWithClient is the loop proper. Split from run so a test can point the
// whole conversation at a local server rather than at Telegram.
func (s *Service) runWithClient(ctx context.Context, doc Document, c *client, generation uint64) {
	me, err := c.getMe(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		// A bad token is permanent and a blocked network is not, but from here
		// they look the same, so the loop backs off and keeps trying either
		// way. What distinguishes them for the operator is the message, which
		// the view carries.
		s.setState(generation, "unreachable", redactToken(err.Error(), doc.Token))
		log.Warnln("[5GPN/BOT] cannot reach Telegram: %v", redactToken(err.Error(), doc.Token))
	} else {
		s.setState(generation, "running", "")
		log.Infoln("[5GPN/BOT] connected as @%s", me.Username)
	}

	admins := make(map[int64]struct{}, len(doc.Admins))
	for _, id := range doc.Admins {
		admins[id] = struct{}{}
	}

	var alerts sync.WaitGroup
	alertsCtx, stopAlerts := context.WithCancel(ctx)
	if doc.Alerts {
		alerts.Add(1)
		go func() {
			defer alerts.Done()
			s.runAlerts(alertsCtx, c, doc)
		}()
	}
	defer func() {
		stopAlerts()
		alerts.Wait()
	}()

	var offset int64
	backoff := pollRetryMin
	for {
		if ctx.Err() != nil {
			return
		}
		updates, err := c.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.setState(generation, "unreachable", redactToken(err.Error(), doc.Token))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > pollRetryMax {
				backoff = pollRetryMax
			}
			continue
		}
		backoff = pollRetryMin
		s.setState(generation, "running", "")

		for _, u := range updates {
			// Cancellation revokes this generation before the replacement is
			// allowed to start. Do not finish a batch under an obsolete admin set
			// when cancellation raced with the long-poll response.
			if ctx.Err() != nil {
				return
			}
			// Advance past every update whether or not it is answered.
			// Telegram replays anything below the offset, so an update the bot
			// declines to act on -- a photo, a stranger's message -- would
			// otherwise be redelivered forever.
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			s.handle(ctx, c, admins, u)
		}
	}
}

// handle answers one update, or does not.
//
// Silence is the default for anything unrecognised and for anyone who is not an
// admin. A bot that says "you are not authorized" confirms to a stranger that
// they have found a live gateway control plane; a bot that says nothing is
// indistinguishable from one that does not exist.
func (s *Service) handle(ctx context.Context, c *client, admins map[int64]struct{}, u update) {
	message := u.Message
	if message == nil || message.Chat == nil || message.From == nil {
		return
	}
	text := strings.TrimSpace(message.Text)
	if !strings.HasPrefix(text, "/") {
		return
	}
	command, argument, _ := strings.Cut(text, " ")
	command = strings.ToLower(strings.TrimSpace(command))
	// Telegram appends @botname to commands in groups.
	if at := strings.IndexByte(command, '@'); at >= 0 {
		command = command[:at]
	}
	argument = strings.TrimSpace(argument)

	// /id is the one command a non-admin gets an answer to, because it is how
	// an operator learns the number to put in the admin list. It discloses only
	// the caller's own id, back to the caller.
	if command == "/id" {
		s.reply(ctx, c, message.Chat.ID, fmt.Sprintf("user id: %d\nchat id: %d", message.From.ID, message.Chat.ID))
		return
	}
	if _, ok := admins[message.From.ID]; !ok {
		return
	}

	switch command {
	case "/start", "/help":
		s.reply(ctx, c, message.Chat.ID, helpText)
	case "/status":
		s.reply(ctx, c, message.Chat.ID, s.renderStatus())
	case "/resolve":
		s.reply(ctx, c, message.Chat.ID, s.renderResolve(argument))
	default:
		s.reply(ctx, c, message.Chat.ID, "unknown command. "+helpText)
	}
}

const helpText = `commands:
/status — resolver, interception and certificate state
/resolve <domain> — what the policy decides for a name
/id — your Telegram id

this bot reads. installing extensions, editing policy and anything touching the
interception CA are console operations and are not available here.`

func (s *Service) reply(ctx context.Context, c *client, chatID int64, text string) {
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := c.sendMessage(sendCtx, chatID, text); err != nil && ctx.Err() == nil {
		log.Warnln("[5GPN/BOT] reply failed: %v", redactToken(err.Error(), c.token))
	}
}

func (s *Service) currentStatus() Status {
	if s.facts.Status == nil {
		return Status{}
	}
	return s.facts.Status()
}

func (s *Service) renderStatus() string {
	status := s.currentStatus()
	var b strings.Builder

	if status.ResolverUp {
		fmt.Fprintf(&b, "resolver: up")
		if status.Gateway != "" {
			fmt.Fprintf(&b, ", gateway %s", status.Gateway)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "queries: %d (%d blocked)\n", status.Queries, status.Blocked)
		if total := status.CacheHits + status.CacheMisses; total > 0 {
			fmt.Fprintf(&b, "cache: %d%% of %d\n", status.CacheHits*100/total, total)
		}
		if len(status.ChinaUpstreams) > 0 || len(status.TrustUpstreams) > 0 {
			fmt.Fprintf(&b, "upstreams: %d china, %d trust\n", len(status.ChinaUpstreams), len(status.TrustUpstreams))
		}
	} else {
		b.WriteString("resolver: not running\n")
	}

	switch {
	case !status.InterceptionInstalled:
		b.WriteString("interception: not installed\n")
	case !status.InterceptionEnabled:
		fmt.Fprintf(&b, "interception: off (%d extensions installed)\n", status.Extensions)
	default:
		fmt.Fprintf(&b, "interception: on, %d of %d extensions enabled\n", status.EnabledExtensions, status.Extensions)
	}

	if status.InterceptionInstalled {
		switch {
		case !status.CertificateLoaded:
			b.WriteString("certificate: none minted yet\n")
		case !status.CertificateCovers:
			// The one piece of status an operator cannot infer elsewhere: the
			// failure presents as a client-side trust error with nothing in the
			// gateway's logs.
			fmt.Fprintf(&b, "certificate: DOES NOT COVER %s\n", strings.Join(status.MissingHosts, ", "))
		default:
			fmt.Fprintf(&b, "certificate: covers every capture host, expires %s\n",
				status.CertificateNotAfter.UTC().Format("2006-01-02"))
		}
	}

	failing := make([]string, 0, len(status.Subscriptions))
	for _, sub := range status.Subscriptions {
		if !sub.OK {
			failing = append(failing, sub.Name)
		}
	}
	sort.Strings(failing)
	if len(failing) > 0 {
		fmt.Fprintf(&b, "subscriptions: %d of %d failing (%s)\n",
			len(failing), len(status.Subscriptions), strings.Join(failing, ", "))
	} else if len(status.Subscriptions) > 0 {
		fmt.Fprintf(&b, "subscriptions: %d, all current\n", len(status.Subscriptions))
	}

	return strings.TrimRight(b.String(), "\n")
}

func (s *Service) renderResolve(argument string) string {
	name := strings.ToLower(strings.TrimSpace(argument))
	if name == "" {
		return "usage: /resolve <domain>"
	}
	if !ValidDomain(name) {
		return fmt.Sprintf("%q is not a valid domain name", argument)
	}
	if s.facts.Resolve == nil {
		return "the resolver is not running"
	}
	explanation, err := s.facts.Resolve(name)
	if err != nil {
		return "resolve failed: " + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s → %s", explanation.Name, explanation.Verdict)
	if explanation.Extension != "" {
		fmt.Fprintf(&b, "\ncaptured by %s", explanation.Extension)
	}
	if explanation.Reason != "" {
		fmt.Fprintf(&b, "\n%s", explanation.Reason)
	}
	return b.String()
}

// errAlertUndeliverable marks a notification nobody could be told about, so the
// monitor does not record the transition as announced.
var errAlertUndeliverable = errors.New("5gpn/bot: no admin could be notified")

// notifyAdmins sends to every configured admin. It reports failure only when
// none of them could be reached: one admin who has blocked the bot must not
// stop the others being told.
func (s *Service) notifyAdmins(ctx context.Context, c *client, admins []int64, text string) error {
	delivered := 0
	for _, id := range admins {
		sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.sendMessage(sendCtx, id, text)
		cancel()
		if err == nil {
			delivered++
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Warnln("[5GPN/BOT] alert to %s failed: %v", strconv.FormatInt(id, 10), redactToken(err.Error(), c.token))
	}
	if delivered == 0 {
		return errAlertUndeliverable
	}
	return nil
}
