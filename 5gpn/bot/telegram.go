package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The Telegram Bot API, in the slice this bot uses: long-poll for updates, send
// a message, and confirm the token at startup.
//
// Hand-written rather than a client library, and the reason is the same one
// that shrank the bot itself. A library brings a complete command router,
// inline keyboards, callback queries, file uploads and webhooks -- an API
// surface for a bot that does far more than read. What this needs is three
// calls. Vendoring a dependency into the process that also terminates DNS and
// forwards traffic, in order to use three of its endpoints, is a cost with no
// matching benefit.

const (
	telegramAPI = "api.telegram.org"
	// Telegram holds a long poll open this long before answering empty. The
	// request timeout has to exceed it or every poll would be cancelled just
	// before the answer arrives.
	pollTimeout    = 25 * time.Second
	requestTimeout = pollTimeout + 20*time.Second
	// Telegram truncates at 4096 characters. Renders are bounded well below
	// this, but a status that grew past it would fail to send rather than be
	// cut, which is a worse failure than being cut.
	maxMessageRunes = 3500
)

type client struct {
	token string
	// base is the API root. It is a field rather than a constant so a test can
	// point the whole client at a local server without a network.
	base string
	http *http.Client
}

func newClient(token string, dial Dialer) *client {
	transport := &http.Transport{
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 64 << 10,
		TLSHandshakeTimeout:    10 * time.Second,
		IdleConnTimeout:        90 * time.Second,
	}
	if dial != nil {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, rawPort, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(rawPort)
			if err != nil {
				return nil, err
			}
			return dial(ctx, host, port)
		}
	}
	return &client{
		token: token,
		base:  "https://" + telegramAPI,
		http:  &http.Client{Transport: transport, Timeout: requestTimeout},
	}
}

func (c *client) endpoint(method string) string {
	return c.base + "/bot" + c.token + "/" + method
}

// call posts a JSON request and decodes the envelope Telegram wraps every
// answer in.
func (c *client) call(ctx context.Context, method string, request any, into any) error {
	var body io.Reader
	if request != nil {
		raw, err := json.Marshal(request)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(method), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		// A non-JSON body is a proxy, a captive portal or a block page. Naming
		// the status is what tells the operator which.
		return fmt.Errorf("telegram %s: HTTP %d with an unreadable body", method, resp.StatusCode)
	}
	if !envelope.OK {
		// Deliberately not including the request: a getUpdates carries nothing
		// sensitive, but sendMessage carries the message, and a failed send
		// logging its own text would put gateway status into the log at a level
		// the operator did not choose.
		return fmt.Errorf("telegram %s: %s", method, envelope.Description)
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, into)
}

type botUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

func (c *client) getMe(ctx context.Context) (botUser, error) {
	var me botUser
	err := c.call(ctx, "getMe", nil, &me)
	return me, err
}

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
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
	} `json:"message"`
}

// getUpdates long-polls. offset acknowledges everything below it, which is how
// Telegram is told an update has been handled -- there is no separate ack, so
// failing to advance the offset replays the same command forever.
func (c *client) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	request := map[string]any{
		"timeout":         int(pollTimeout / time.Second),
		"allowed_updates": []string{"message"},
	}
	if offset > 0 {
		request["offset"] = offset
	}
	var updates []update
	err := c.call(ctx, "getUpdates", request, &updates)
	return updates, err
}

func (c *client) sendMessage(ctx context.Context, chatID int64, text string) error {
	return c.call(ctx, "sendMessage", map[string]any{
		"chat_id": chatID,
		"text":    truncateRunes(text, maxMessageRunes),
		// No parse mode. Every rendered value below can contain a hostname, an
		// error string or an extension name the operator did not write, and
		// formatting them means escaping them correctly in every path. Plain
		// text has no escaping to get wrong.
		"disable_web_page_preview": true,
	}, nil)
}

func truncateRunes(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit]) + "\n… truncated"
}

// redactToken keeps a bot token out of a message an operator will paste into an
// issue. The token appears in every request URL, so a transport error carries
// it verbatim.
func redactToken(message, token string) string {
	if token == "" {
		return message
	}
	return strings.ReplaceAll(message, token, "«token»")
}
