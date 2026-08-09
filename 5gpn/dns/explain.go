package dns

import (
	"context"
	"strings"

	D "github.com/miekg/dns"
)

// RuleRef names the policy rule that decided a name.
type RuleRef struct {
	ID      string      `json:"id"`
	Kind    MatcherKind `json:"kind"`
	Value   string      `json:"value"`
	Intent  Intent      `json:"intent"`
	Entries int         `json:"entries"`
}

// Explanation is the resolve diagnostic: what this name does right now, and
// what decided it.
type Explanation struct {
	Name     string   `json:"name"`
	Verdict  Verdict  `json:"verdict"`
	Rule     *RuleRef `json:"rule,omitempty"`
	Capture  *Capture `json:"capture,omitempty"`
	Fallback Fallback `json:"fallback"`
	Gateway  string   `json:"gateway,omitempty"`
	Rcode    string   `json:"rcode"`
	Upstream string   `json:"upstream,omitempty"`
	CacheHit bool     `json:"cacheHit"`
	Answers  []string `json:"answers,omitempty"`
	// Origin is what mihomo would get for the same name after the sniffer,
	// which is a different question and routinely a different answer.
	Origin []string `json:"origin,omitempty"`
}

// Explain answers "what happens to this name" by running the real resolution
// path against a synthetic query.
//
// Running it rather than describing it is the whole point. The previous
// diagnostic reimplemented the precedence and drifted from it, so it could
// report a verdict the resolver did not produce -- which is worse than no
// diagnostic, because an operator trusts it enough to stop looking.
func (r *Resolver) Explain(ctx context.Context, name string) Explanation {
	name = strings.TrimSpace(name)
	out := Explanation{Name: normalizeDomain(name)}
	if out.Name == "" {
		return out
	}
	runtime := r.snapshot()
	if runtime == nil || runtime.policy == nil {
		return out
	}

	decision := r.decide(runtime, out.Name)
	out.Capture = decision.Capture
	out.Fallback = decision.policy.fallback()
	if gw := runtime.gateway; gw.IsValid() && !gw.IsUnspecified() {
		out.Gateway = gw.String()
	}
	if decision.Rule != nil {
		out.Rule = &RuleRef{
			ID:      decision.Rule.ID,
			Kind:    decision.Rule.Kind,
			Value:   decision.Rule.Value,
			Intent:  decision.Rule.Intent,
			Entries: decision.Rule.entries,
		}
	}

	req := new(D.Msg)
	req.SetQuestion(D.Fqdn(out.Name), D.TypeA)
	var t trace
	resp := r.resolveRuntimeDecision(ctx, req.Question[0], req, &t, runtime, &decision)

	out.Verdict = Verdict{Verdict: t.verdict, Reason: t.reason}
	if out.Verdict.Verdict == "" && out.Verdict.Reason == "" {
		out.Verdict = decision.Verdict
	}
	out.Upstream = t.upstream
	out.CacheHit = t.cacheHit
	if resp != nil {
		out.Rcode = D.RcodeToString[resp.Rcode]
		out.Answers = answerIPs(resp, 16)
	}

	// The origin lookup is reported alongside because the two diverge exactly
	// where an operator is most likely to be confused: a steered name answers
	// with the gateway here and with the real origin there, and seeing only the
	// first reads as "DNS is broken".
	originReq := new(D.Msg)
	originReq.SetQuestion(D.Fqdn(out.Name), D.TypeA)
	if tryAcquire(r.originSem) {
		originResp := r.resolveOriginRuntimeCapture(ctx, originReq.Question[0], originReq, runtime, decision.Capture)
		releaseAdmission(r.originSem)
		if originResp != nil && originResp.Rcode == D.RcodeSuccess {
			out.Origin = answerIPs(originResp, 16)
		}
	}
	return out
}
