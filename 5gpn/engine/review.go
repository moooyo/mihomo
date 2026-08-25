package engine

import "encoding/json"

// ReviewContractVersion is the control-plane contract shared by capability
// advertisement, review responses, and confirmation writes.
const ReviewContractVersion = 8

const (
	actionReviewKindScript      = "script"
	actionReviewKindJQ          = "jq"
	actionReviewKindReject      = "reject"
	actionReviewKindMock        = "mock"
	actionReviewKindHeaders     = "headers"
	actionReviewKindRewrite     = "rewrite"
	actionReviewKindReplaceBody = "replace_body"
)

// ActionReview is the bounded, body-free review projection for one action.
// It is deliberately independent of ScriptRule so adding a runtime-only field
// cannot accidentally publish source code or compiled state through the API.
type ActionReview struct {
	ID       string   `json:"id"`
	Phase    string   `json:"phase"`
	Hosts    []string `json:"hosts,omitempty"`
	Schemes  []string `json:"schemes,omitempty"`
	Methods  []string `json:"methods,omitempty"`
	Path     string   `json:"path,omitempty"`
	Statuses []int    `json:"statuses,omitempty"`

	Kind        string            `json:"kind"`
	EnabledWhen *ActionReviewGate `json:"enabled_when,omitempty"`
	BodyMode    string            `json:"body_mode"`

	Entry      string `json:"entry,omitempty"`
	SourceKind string `json:"source_kind,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	CodeDigest string `json:"code_digest,omitempty"`
	CodeBytes  int64  `json:"code_bytes,omitempty"`

	ReviewDigest string `json:"review_digest"`
	TimeoutMS    int    `json:"timeout_ms"`
	MaxBodyBytes int64  `json:"max_body_bytes"`

	Mock        *ActionReviewMock        `json:"mock,omitempty"`
	Headers     *ActionReviewHeaderEdits `json:"headers,omitempty"`
	Rewrite     *ActionReviewURLRewrite  `json:"rewrite,omitempty"`
	ReplaceBody *ActionReviewBodyReplace `json:"replace_body,omitempty"`
}

type ActionReviewGate struct {
	Key    string `json:"key"`
	Equals string `json:"equals"`
}

type ActionReviewMock struct {
	Status  int                       `json:"status"`
	Headers map[string]string         `json:"headers,omitempty"`
	Body    ActionReviewMockBodyState `json:"body"`
}

type ActionReviewMockBodyState struct {
	Kind   string `json:"kind"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type ActionReviewHeaderEdits struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

type ActionReviewURLRewrite struct {
	Pattern string `json:"pattern"`
	To      string `json:"to"`
	Status  int    `json:"status"`
}

type ActionReviewBodyReplace struct {
	Pattern  string                       `json:"pattern"`
	To       string                       `json:"to"`
	ValueMap map[string]map[string]string `json:"value_map,omitempty"`
}

func actionReviewOf(rule ScriptRule) ActionReview {
	review := ActionReview{
		ID:           rule.ID,
		Phase:        rule.Phase,
		Hosts:        append([]string(nil), rule.Match.Hosts...),
		Schemes:      append([]string(nil), rule.Match.Schemes...),
		Methods:      append([]string(nil), rule.Match.Methods...),
		Path:         rule.Match.PathRegex,
		Statuses:     append([]int(nil), rule.Match.StatusCodes...),
		BodyMode:     rule.BodyMode,
		TimeoutMS:    rule.TimeoutMS,
		MaxBodyBytes: rule.MaxBodyBytes,
	}
	if rule.EnabledWhen != nil {
		review.EnabledWhen = &ActionReviewGate{
			Key:    rule.EnabledWhen.Key,
			Equals: rule.EnabledWhen.Equals,
		}
	}

	switch {
	case rule.JQProgram != "":
		review.Kind = actionReviewKindJQ
		review.CodeDigest = digestText(rule.JQProgram)
		review.CodeBytes = int64(len(rule.JQProgram))
	case rule.Reject:
		review.Kind = actionReviewKindReject
	case rule.Mock != nil:
		review.Kind = actionReviewKindMock
		review.Mock = reviewMock(rule.Mock)
	case rule.Headers != nil:
		review.Kind = actionReviewKindHeaders
		review.Headers = &ActionReviewHeaderEdits{
			Set:    copyReviewStringMap(rule.Headers.Set),
			Remove: append([]string(nil), rule.Headers.Remove...),
		}
	case rule.Rewrite != nil:
		review.Kind = actionReviewKindRewrite
		review.Rewrite = &ActionReviewURLRewrite{
			Pattern: rule.Rewrite.Pattern,
			To:      rule.Rewrite.To,
			Status:  rule.Rewrite.Status,
		}
	case rule.ReplaceBody != nil:
		review.Kind = actionReviewKindReplaceBody
		review.ReplaceBody = &ActionReviewBodyReplace{
			Pattern:  rule.ReplaceBody.Pattern,
			To:       rule.ReplaceBody.To,
			ValueMap: copyReviewNestedStringMap(rule.ReplaceBody.ValueMap),
		}
	default:
		review.Kind = actionReviewKindScript
		review.Entry = rule.Entry
		if review.Entry == "" {
			review.Entry = "native"
		}
		review.SourceKind = "inline"
		if rule.ScriptURL != "" {
			review.SourceKind = "url"
			review.SourceURL = rule.ScriptURL
		}
		review.CodeDigest = rule.ScriptDigest
		review.CodeBytes = int64(len(rule.ScriptBody))
	}

	review.ReviewDigest = actionReviewDigest(review)
	return review
}

func reviewMock(mock *MockResponse) *ActionReviewMock {
	status := mock.Status
	if status == 0 {
		status = 200
	}
	// Published modules have already passed MockResponse.validate, so decoding
	// cannot fail while projecting the immutable committed snapshot.
	body, _ := mock.bytes()
	bodyKind := "empty"
	switch {
	case mock.Body != nil:
		bodyKind = "text"
	case mock.Base64Body != nil:
		bodyKind = "base64"
	}
	return &ActionReviewMock{
		Status:  status,
		Headers: copyReviewStringMap(mock.Headers),
		Body: ActionReviewMockBodyState{
			Kind:   bodyKind,
			Bytes:  int64(len(body)),
			SHA256: digestText(string(body)),
		},
	}
}

func actionReviewDigest(review ActionReview) string {
	payload := actionReviewDigestV1{
		ID: review.ID, Phase: review.Phase,
		Hosts: review.Hosts, Schemes: review.Schemes, Methods: review.Methods,
		Path: review.Path, Statuses: review.Statuses,
		Kind: review.Kind, BodyMode: review.BodyMode,
		Entry: review.Entry, SourceKind: review.SourceKind, SourceURL: review.SourceURL,
		CodeDigest: review.CodeDigest, CodeBytes: review.CodeBytes,
		TimeoutMS: review.TimeoutMS, MaxBodyBytes: review.MaxBodyBytes,
	}
	if review.EnabledWhen != nil {
		payload.EnabledWhen = &actionReviewDigestGateV1{
			Key: review.EnabledWhen.Key, Equals: review.EnabledWhen.Equals,
		}
	}
	if review.Mock != nil {
		payload.Mock = &actionReviewDigestMockV1{
			Status: review.Mock.Status, Headers: review.Mock.Headers,
			BodyKind: review.Mock.Body.Kind, BodyBytes: review.Mock.Body.Bytes,
			BodySHA256: review.Mock.Body.SHA256,
		}
	}
	if review.Headers != nil {
		payload.Headers = &actionReviewDigestHeadersV1{
			Set: review.Headers.Set, Remove: review.Headers.Remove,
		}
	}
	if review.Rewrite != nil {
		payload.Rewrite = &actionReviewDigestRewriteV1{
			Pattern: review.Rewrite.Pattern, To: review.Rewrite.To, Status: review.Rewrite.Status,
		}
	}
	if review.ReplaceBody != nil {
		payload.ReplaceBody = &actionReviewDigestReplaceBodyV1{
			Pattern: review.ReplaceBody.Pattern, To: review.ReplaceBody.To,
			ValueMap: review.ReplaceBody.ValueMap,
		}
	}
	// The private versioned payload is deliberately separate from the response
	// DTO. Presentation-only fields and JSON tag changes must not silently alter
	// an operator's action identity. encoding/json sorts string map keys.
	raw, _ := json.Marshal(payload)
	return digestText("5gpn.io/action-review/v1\n" + string(raw))
}

type actionReviewDigestV1 struct {
	ID           string                           `json:"id"`
	Phase        string                           `json:"phase"`
	Hosts        []string                         `json:"hosts,omitempty"`
	Schemes      []string                         `json:"schemes,omitempty"`
	Methods      []string                         `json:"methods,omitempty"`
	Path         string                           `json:"path,omitempty"`
	Statuses     []int                            `json:"statuses,omitempty"`
	Kind         string                           `json:"kind"`
	EnabledWhen  *actionReviewDigestGateV1        `json:"enabled_when,omitempty"`
	BodyMode     string                           `json:"body_mode"`
	Entry        string                           `json:"entry,omitempty"`
	SourceKind   string                           `json:"source_kind,omitempty"`
	SourceURL    string                           `json:"source_url,omitempty"`
	CodeDigest   string                           `json:"code_digest,omitempty"`
	CodeBytes    int64                            `json:"code_bytes,omitempty"`
	TimeoutMS    int                              `json:"timeout_ms"`
	MaxBodyBytes int64                            `json:"max_body_bytes"`
	Mock         *actionReviewDigestMockV1        `json:"mock,omitempty"`
	Headers      *actionReviewDigestHeadersV1     `json:"headers,omitempty"`
	Rewrite      *actionReviewDigestRewriteV1     `json:"rewrite,omitempty"`
	ReplaceBody  *actionReviewDigestReplaceBodyV1 `json:"replace_body,omitempty"`
}

type actionReviewDigestGateV1 struct {
	Key    string `json:"key"`
	Equals string `json:"equals"`
}

type actionReviewDigestMockV1 struct {
	Status     int               `json:"status"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyKind   string            `json:"body_kind"`
	BodyBytes  int64             `json:"body_bytes"`
	BodySHA256 string            `json:"body_sha256"`
}

type actionReviewDigestHeadersV1 struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

type actionReviewDigestRewriteV1 struct {
	Pattern string `json:"pattern"`
	To      string `json:"to"`
	Status  int    `json:"status"`
}

type actionReviewDigestReplaceBodyV1 struct {
	Pattern  string                       `json:"pattern"`
	To       string                       `json:"to"`
	ValueMap map[string]map[string]string `json:"value_map,omitempty"`
}

func copyReviewStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func copyReviewNestedStringMap(source map[string]map[string]string) map[string]map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]map[string]string, len(source))
	for key, value := range source {
		clone[key] = copyReviewStringMap(value)
	}
	return clone
}
