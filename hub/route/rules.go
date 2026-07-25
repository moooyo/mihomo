package route

import (
	"fmt"
	"time"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)
	if !embedMode { // disallow update/patch rules in embed mode
		r.Patch("/disable", disableRules)
	}
	return r
}

type Rule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size"`

	// Extra contains information from RuleWrapper
	Extra *RuleExtra `json:"extra,omitempty"`
}

type RuleExtra struct {
	Disabled  bool      `json:"disabled"`
	HitCount  uint64    `json:"hitCount"`
	HitAt     time.Time `json:"hitAt"`
	MissCount uint64    `json:"missCount"`
	MissAt    time.Time `json:"missAt"`
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rawRules := tunnel.Rules()
	rules := make([]Rule, 0, len(rawRules))
	for index, rule := range rawRules {
		r := Rule{
			Index:   index,
			Type:    rule.RuleType().String(),
			Payload: rule.Payload(),
			Proxy:   rule.Adapter(),
			Size:    -1,
		}
		if ruleWrapper, ok := rule.(constant.RuleWrapper); ok {
			r.Extra = &RuleExtra{
				Disabled:  ruleWrapper.IsDisabled(),
				HitCount:  ruleWrapper.HitCount(),
				HitAt:     ruleWrapper.HitAt(),
				MissCount: ruleWrapper.MissCount(),
				MissAt:    ruleWrapper.MissAt(),
			}
			rule = ruleWrapper.Unwrap() // unwrap RuleWrapper
		}
		if rule.RuleType() == constant.GEOIP || rule.RuleType() == constant.GEOSITE {
			r.Size = rule.(constant.RuleGroup).GetRecodeSize()
		}
		rules = append(rules, r)

	}

	render.JSON(w, r, render.M{
		"rules": rules,
	})
}

// disableRules disable or enable rules by their indexes.
func disableRules(w http.ResponseWriter, r *http.Request) {
	// key: rule index, value: disabled
	var payload map[int]bool
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if len(payload) != 0 {
		rules := tunnel.Rules()

		// Validate the entire payload before mutating anything. A disabled rule
		// returns "no match", so disabling an overlay anchor or the egress
		// terminator silently removes it from the match path with no config
		// reload and no log. Applying entries as they are iterated would also
		// make a rejected payload land partially, in map iteration order.
		for index := range payload {
			if index < 0 || index >= len(rules) {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError(fmt.Sprintf("rule index %d is out of range", index)))
				return
			}
			if _, ok := rules[index].(constant.RuleWrapper); !ok {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError(fmt.Sprintf("rule %d cannot be disabled", index)))
				return
			}
			if reason := overlayProtectedRule(rules, index); reason != "" {
				render.Status(r, http.StatusConflict)
				render.JSON(w, r, newError(reason))
				return
			}
		}

		for index, disabled := range payload {
			rules[index].(constant.RuleWrapper).SetDisabled(disabled)
		}
	}

	render.NoContent(w, r)
}

// overlayProtectedRule reports why a rule may not be disabled, or "" when it
// may be.
//
// Protection applies whenever the rule list declares anchors, not only when a
// generation happens to be active: the anchors and their terminator are the
// structure the overlay is validated against, and letting the controller
// dismantle it out of band would make every later validation meaningless.
func overlayProtectedRule(rules []constant.Rule, index int) string {
	inner := rules[index]
	if w, ok := inner.(constant.RuleWrapper); ok {
		inner = w.Unwrap()
	}
	switch inner.RuleType() {
	case constant.RuntimeOverlayClient, constant.RuntimeOverlayEgress:
		return fmt.Sprintf("rule %d is a runtime-overlay anchor and cannot be disabled", index)
	}

	// The deny terminator immediately after the egress anchor, and every deny
	// guard that precedes the anchors, are load-bearing: without them a
	// processor-originated connection that fails the capability check would
	// continue into the operator's rules.
	for i, r := range rules {
		candidate := r
		if w, ok := candidate.(constant.RuleWrapper); ok {
			candidate = w.Unwrap()
		}
		if candidate.RuleType() != constant.RuntimeOverlayEgress {
			continue
		}
		if index <= i+1 {
			return fmt.Sprintf("rule %d is a protected system guard preceding the runtime-overlay egress terminator", index)
		}
		break
	}
	return ""
}
