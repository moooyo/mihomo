package engine

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func reviewTestMatch() ActionMatch {
	return ActionMatch{
		Hosts:       []string{"review.example.com"},
		Schemes:     []string{"https"},
		Methods:     []string{"POST"},
		PathRegex:   "^/review(?:\\?.*)?$",
		StatusCodes: []int{200},
	}
}

func reviewTestRule(id string) ScriptRule {
	return ScriptRule{
		ID: id, Phase: "response", Match: reviewTestMatch(), BodyMode: "text",
		TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
	}
}

func cloneReviewTestRule(rule ScriptRule) ScriptRule {
	clone := rule
	clone.Match.Hosts = append([]string(nil), rule.Match.Hosts...)
	clone.Match.Schemes = append([]string(nil), rule.Match.Schemes...)
	clone.Match.Methods = append([]string(nil), rule.Match.Methods...)
	clone.Match.StatusCodes = append([]int(nil), rule.Match.StatusCodes...)
	if rule.EnabledWhen != nil {
		gate := *rule.EnabledWhen
		clone.EnabledWhen = &gate
	}
	if rule.Mock != nil {
		mock := *rule.Mock
		mock.Headers = copyReviewStringMap(rule.Mock.Headers)
		if rule.Mock.Body != nil {
			body := *rule.Mock.Body
			mock.Body = &body
		}
		if rule.Mock.Base64Body != nil {
			body := *rule.Mock.Base64Body
			mock.Base64Body = &body
		}
		clone.Mock = &mock
	}
	if rule.Headers != nil {
		headers := *rule.Headers
		headers.Set = copyReviewStringMap(rule.Headers.Set)
		headers.Remove = append([]string(nil), rule.Headers.Remove...)
		clone.Headers = &headers
	}
	if rule.Rewrite != nil {
		rewrite := *rule.Rewrite
		clone.Rewrite = &rewrite
	}
	if rule.ReplaceBody != nil {
		replace := *rule.ReplaceBody
		replace.ValueMap = copyReviewNestedStringMap(rule.ReplaceBody.ValueMap)
		clone.ReplaceBody = &replace
	}
	return clone
}

func TestActionReviewCoversEveryKindWithoutPublishingBodies(t *testing.T) {
	scriptBody := "function transform(context) { return {abort: true}; }"
	jqBody := `del(.secret)`
	mockBody := "private mock body"
	inlineBody := "function transform(context) { return {}; }"

	script := reviewTestRule("script-url")
	script.Entry = scriptEntryProxyCompat
	script.ScriptURL = "https://scripts.example.com/review.js"
	script.ScriptBody = scriptBody
	script.ScriptDigest = digestText(scriptBody)
	script.EnabledWhen = &ActionGate{Key: "mode", Equals: "enabled"}

	jq := reviewTestRule("jq")
	jq.JQProgram = jqBody

	reject := reviewTestRule("reject")
	reject.Reject = true

	mock := reviewTestRule("mock")
	mock.Mock = &MockResponse{
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    &mockBody,
	}

	headers := reviewTestRule("headers")
	headers.Headers = &HeaderEdits{
		Set: map[string]string{"X-Review": "yes"}, Remove: []string{"X-Old"},
	}

	rewrite := reviewTestRule("rewrite")
	rewrite.Phase = "request"
	rewrite.Match.StatusCodes = nil
	rewrite.Rewrite = &URLRewrite{
		Pattern: `^https://review\.example\.com/(.*)$`,
		To:      `https://origin.example.net/$1`,
	}

	replace := reviewTestRule("replace-body")
	replace.ReplaceBody = &BodyReplace{
		Pattern: `"region":"[A-Z]+"`,
		To:      `"region":"{{settings.region}}"`,
		ValueMap: map[string]map[string]string{
			"region": {"US": "USA"},
		},
	}

	inline := reviewTestRule("script-inline")
	inline.Entry = ""
	inline.ScriptBody = inlineBody
	inline.ScriptDigest = digestText(inlineBody)

	manifestBody := "manifest body must not be returned"
	module := Module{
		ID: "review.plugin", Version: "1.0.0", Name: "Review plugin",
		Source:       ModuleSource{Body: manifestBody, Digest: digestText(manifestBody)},
		CaptureHosts: []string{"review.example.com"}, CaptureDNS: "trust",
		EgressGroup: defaultExtensionEgressGroup,
		Scripts:     []ScriptRule{script, jq, reject, mock, headers, rewrite, replace, inline},
	}
	detail := detailOf(module)
	if detail.ReviewContract != ReviewContractVersion {
		t.Fatalf("review contract = %d, want %d", detail.ReviewContract, ReviewContractVersion)
	}
	if len(detail.Actions) != 8 {
		t.Fatalf("action reviews = %d, want 8", len(detail.Actions))
	}

	byID := make(map[string]ActionReview, len(detail.Actions))
	kinds := make(map[string]bool)
	for _, action := range detail.Actions {
		byID[action.ID] = action
		kinds[action.Kind] = true
		if len(action.ReviewDigest) != 64 {
			t.Errorf("action %s review digest = %q", action.ID, action.ReviewDigest)
		}
	}
	for _, kind := range []string{
		actionReviewKindScript, actionReviewKindJQ, actionReviewKindReject,
		actionReviewKindMock, actionReviewKindHeaders, actionReviewKindRewrite,
		actionReviewKindReplaceBody,
	} {
		if !kinds[kind] {
			t.Errorf("review omits action kind %q", kind)
		}
	}

	urlScript := byID["script-url"]
	if urlScript.Entry != scriptEntryProxyCompat || urlScript.SourceKind != "url" ||
		urlScript.SourceURL != script.ScriptURL || urlScript.CodeDigest != script.ScriptDigest ||
		urlScript.CodeBytes != int64(len(scriptBody)) {
		t.Fatalf("URL script review = %+v", urlScript)
	}
	if urlScript.EnabledWhen == nil || urlScript.EnabledWhen.Key != "mode" {
		t.Fatalf("script gate = %+v", urlScript.EnabledWhen)
	}
	inlineScript := byID["script-inline"]
	if inlineScript.Entry != "native" || inlineScript.SourceKind != "inline" || inlineScript.SourceURL != "" {
		t.Fatalf("inline script review = %+v", inlineScript)
	}
	jqReview := byID["jq"]
	if jqReview.CodeDigest != digestText(jqBody) || jqReview.CodeBytes != int64(len(jqBody)) {
		t.Fatalf("jq review = %+v", jqReview)
	}
	mockReview := byID["mock"].Mock
	if mockReview == nil || mockReview.Status != 200 || mockReview.Body.Kind != "text" ||
		mockReview.Body.Bytes != int64(len(mockBody)) || mockReview.Body.SHA256 != digestText(mockBody) {
		t.Fatalf("mock review = %+v", mockReview)
	}

	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{manifestBody, scriptBody, inlineBody, jqBody, mockBody} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("review response published hidden body %q", secret)
		}
	}

	module.Scripts[0].Match.Hosts[0] = "changed.example.com"
	module.Scripts[0].EnabledWhen.Key = "changed"
	module.Scripts[3].Mock.Headers["Content-Type"] = "text/plain"
	module.Scripts[4].Headers.Set["X-Review"] = "changed"
	module.Scripts[4].Headers.Remove[0] = "X-Changed"
	module.Scripts[6].ReplaceBody.ValueMap["region"]["US"] = "changed"
	if byID["script-url"].Hosts[0] != "review.example.com" || byID["script-url"].EnabledWhen.Key != "mode" ||
		byID["mock"].Mock.Headers["Content-Type"] != "application/json" ||
		byID["headers"].Headers.Set["X-Review"] != "yes" || byID["headers"].Headers.Remove[0] != "X-Old" ||
		byID["replace-body"].ReplaceBody.ValueMap["region"]["US"] != "USA" {
		t.Fatal("action review aliases mutable runtime state")
	}
}

func TestActionReviewDigestCoversHiddenDeclarations(t *testing.T) {
	scriptBody := "function transform(context) { return {}; }"
	script := reviewTestRule("script")
	script.ScriptURL = "https://scripts.example.com/a.js"
	script.ScriptBody = scriptBody
	script.ScriptDigest = digestText(scriptBody)
	script.EnabledWhen = &ActionGate{Key: "mode", Equals: "a"}

	jq := reviewTestRule("jq")
	jq.JQProgram = `del(.a)`

	mockBody := "a"
	mock := reviewTestRule("mock")
	mock.Mock = &MockResponse{Headers: map[string]string{"X-A": "1"}, Body: &mockBody}

	headers := reviewTestRule("headers")
	headers.Headers = &HeaderEdits{Set: map[string]string{"X-A": "1", "X-B": "2"}}

	rewrite := reviewTestRule("rewrite")
	rewrite.Phase = "request"
	rewrite.Match.StatusCodes = nil
	rewrite.Rewrite = &URLRewrite{Pattern: "^https://a/", To: "https://b/"}

	replace := reviewTestRule("replace")
	replace.ReplaceBody = &BodyReplace{
		Pattern: "a", To: "{{settings.region}}",
		ValueMap: map[string]map[string]string{"region": {"a": "b"}},
	}

	tests := []struct {
		name   string
		before ScriptRule
		change func(*ScriptRule)
	}{
		{name: "gate", before: script, change: func(rule *ScriptRule) { rule.EnabledWhen.Equals = "b" }},
		{name: "matcher path", before: script, change: func(rule *ScriptRule) { rule.Match.PathRegex = "^/changed$" }},
		{name: "body mode", before: script, change: func(rule *ScriptRule) { rule.BodyMode = "binary" }},
		{name: "entry", before: script, change: func(rule *ScriptRule) { rule.Entry = scriptEntryProxyCompat }},
		{name: "script URL", before: script, change: func(rule *ScriptRule) { rule.ScriptURL = "https://scripts.example.com/b.js" }},
		{name: "script digest", before: script, change: func(rule *ScriptRule) { rule.ScriptDigest = strings.Repeat("f", 64) }},
		{name: "timeout", before: script, change: func(rule *ScriptRule) { rule.TimeoutMS++ }},
		{name: "max body", before: script, change: func(rule *ScriptRule) { rule.MaxBodyBytes++ }},
		{name: "jq code", before: jq, change: func(rule *ScriptRule) { rule.JQProgram = `del(.b)` }},
		{name: "mock body", before: mock, change: func(rule *ScriptRule) { body := "b"; rule.Mock.Body = &body }},
		{name: "header value", before: headers, change: func(rule *ScriptRule) { rule.Headers.Set["X-A"] = "changed" }},
		{name: "rewrite target", before: rewrite, change: func(rule *ScriptRule) { rule.Rewrite.To = "https://c/" }},
		{name: "replacement map", before: replace, change: func(rule *ScriptRule) { rule.ReplaceBody.ValueMap["region"]["a"] = "c" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := cloneReviewTestRule(test.before)
			after := cloneReviewTestRule(test.before)
			test.change(&after)
			if actionReviewOf(before).ReviewDigest == actionReviewOf(after).ReviewDigest {
				t.Fatalf("review digest did not cover %s", test.name)
			}
		})
	}

	orderedA := cloneReviewTestRule(headers)
	orderedB := cloneReviewTestRule(headers)
	orderedB.Headers.Set = map[string]string{"X-B": "2", "X-A": "1"}
	if actionReviewOf(orderedA).ReviewDigest != actionReviewOf(orderedB).ReviewDigest {
		t.Fatal("review digest depends on map insertion order")
	}
}

func TestActionReviewSummarisesDecodedBase64MockBody(t *testing.T) {
	wireBody := []byte{0, 1, 2, 3, 255}
	encoded := base64.StdEncoding.EncodeToString(wireBody)
	rule := reviewTestRule("base64-mock")
	rule.Mock = &MockResponse{Base64Body: &encoded}

	review := actionReviewOf(rule)
	if review.Mock == nil || review.Mock.Body.Kind != "base64" ||
		review.Mock.Body.Bytes != int64(len(wireBody)) ||
		review.Mock.Body.SHA256 != digestText(string(wireBody)) {
		t.Fatalf("base64 mock review = %+v", review.Mock)
	}
	raw, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), encoded) {
		t.Fatal("base64 mock review published the encoded body")
	}
}

func TestActionReviewDigestSurvivesJSONRoundTrip(t *testing.T) {
	scriptBody := "function transform(context) { return {}; }"
	script := reviewTestRule("round-trip-script")
	script.Entry = scriptEntryProxyCompat
	script.ScriptURL = "https://scripts.example.com/round-trip.js"
	script.ScriptBody = scriptBody
	script.ScriptDigest = digestText(scriptBody)
	script.EnabledWhen = &ActionGate{Key: "mode", Equals: "script"}

	replace := reviewTestRule("round-trip-replace")
	replace.ReplaceBody = &BodyReplace{
		Pattern: "old", To: "{{settings.mode}}",
		ValueMap: map[string]map[string]string{"mode": {"a": "new"}},
	}

	for _, rule := range []ScriptRule{script, replace} {
		before := actionReviewOf(rule).ReviewDigest
		raw, err := json.Marshal(rule)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ScriptRule
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if after := actionReviewOf(decoded).ReviewDigest; after != before {
			t.Fatalf("action %s review digest changed across JSON round trip: %s -> %s", rule.ID, before, after)
		}
	}
}
