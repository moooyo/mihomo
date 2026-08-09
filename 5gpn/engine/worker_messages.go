package engine

import (
	"errors"
	"fmt"

	"github.com/metacubex/http"
)

const (
	workerPerProcessMemoryBytes = uint64(512 << 20)
	workerAggregateMemoryBytes  = uint64(1 << 30)
	workerMaximumProcesses      = uint32(2)
)

// ErrHardIsolationUnavailable is returned when code cannot be validated or
// executed inside the mandatory OS memory boundary. Callers must never retry
// the operation in the parent process.
var ErrHardIsolationUnavailable = errors.New("extension hard isolation is unavailable")

// ErrWorkerCapacity is a transient refusal: both fixed worker-memory slots are
// already in use. Callers must not queue raw configurations or action bodies.
var ErrWorkerCapacity = errors.New("extension worker capacity is busy")

type workerReadyMetadata struct {
	Protocol uint16 `msgpack:"protocol"`
}

type workerErrorMetadata struct {
	Code    string `msgpack:"code"`
	Message string `msgpack:"message"`
}

type workerActionMetadata struct {
	ModuleID      string                 `msgpack:"module_id"`
	Network       bool                   `msgpack:"network"`
	Persistent    bool                   `msgpack:"persistent"`
	Rule          workerRuleMetadata     `msgpack:"rule"`
	Settings      map[string]any         `msgpack:"settings"`
	Request       workerMessageMetadata  `msgpack:"request"`
	Response      *workerMessageMetadata `msgpack:"response"`
	TimeoutMillis int64                  `msgpack:"timeout_millis"`
}

type workerRuleMetadata struct {
	ID           string `msgpack:"id"`
	Phase        string `msgpack:"phase"`
	ScriptURL    string `msgpack:"script_url"`
	ScriptDigest string `msgpack:"script_digest"`
	ScriptBody   string `msgpack:"script_body"`
	BodyMode     string `msgpack:"body_mode"`
	Entry        string `msgpack:"entry"`
	JQProgram    string `msgpack:"jq_program"`
	TimeoutMS    int    `msgpack:"timeout_ms"`
	MaxBodyBytes int64  `msgpack:"max_body_bytes"`
}

type workerMessageMetadata struct {
	URL        string              `msgpack:"url"`
	Method     string              `msgpack:"method"`
	Headers    map[string][]string `msgpack:"headers"`
	Trailers   map[string][]string `msgpack:"trailers"`
	StatusCode int                 `msgpack:"status_code"`
}

type workerResultMetadata struct {
	URL             string              `msgpack:"url"`
	Headers         map[string][]string `msgpack:"headers"`
	Trailers        map[string][]string `msgpack:"trailers"`
	StatusCode      int                 `msgpack:"status_code"`
	Synthetic       bool                `msgpack:"synthetic"`
	Abort           bool                `msgpack:"abort"`
	ChangedURL      bool                `msgpack:"changed_url"`
	ChangedBody     bool                `msgpack:"changed_body"`
	ChangedHeaders  bool                `msgpack:"changed_headers"`
	ChangedTrailers bool                `msgpack:"changed_trailers"`
	ChangedStatus   bool                `msgpack:"changed_status"`
}

type workerNetworkRequestMetadata struct {
	URL     string              `msgpack:"url"`
	Method  string              `msgpack:"method"`
	Headers map[string][]string `msgpack:"headers"`
	HasBody bool                `msgpack:"has_body"`
	Wait    bool                `msgpack:"wait"`
}

type workerNetworkResponseMetadata struct {
	URL        string              `msgpack:"url"`
	StatusCode int                 `msgpack:"status_code"`
	Headers    map[string][]string `msgpack:"headers"`
	Trailers   map[string][]string `msgpack:"trailers"`
	Error      string              `msgpack:"error"`
}

type workerStorageRequestMetadata struct {
	Operation string `msgpack:"operation"`
	Key       string `msgpack:"key"`
}

type workerStorageResponseMetadata struct {
	OK     bool   `msgpack:"ok"`
	Exists bool   `msgpack:"exists"`
	Error  string `msgpack:"error"`
}

type workerLogMetadata struct {
	Level   string `msgpack:"level"`
	Message string `msgpack:"message"`
}

type workerAckMetadata struct {
	OK bool `msgpack:"ok"`
}

func workerRuleFrom(rule ScriptRule) workerRuleMetadata {
	return workerRuleMetadata{
		ID: rule.ID, Phase: rule.Phase, ScriptURL: rule.ScriptURL,
		ScriptDigest: rule.ScriptDigest, ScriptBody: rule.ScriptBody,
		BodyMode: rule.BodyMode, Entry: rule.Entry, JQProgram: rule.JQProgram,
		TimeoutMS: rule.TimeoutMS, MaxBodyBytes: rule.MaxBodyBytes,
	}
}

func (rule workerRuleMetadata) scriptRule(settings map[string]any) ScriptRule {
	return ScriptRule{
		ID: rule.ID, Phase: rule.Phase, ScriptURL: rule.ScriptURL,
		ScriptDigest: rule.ScriptDigest, ScriptBody: rule.ScriptBody,
		BodyMode: rule.BodyMode, Entry: rule.Entry, JQProgram: rule.JQProgram,
		TimeoutMS: rule.TimeoutMS, MaxBodyBytes: rule.MaxBodyBytes,
		settings: settings,
	}
}

func workerMessageFrom(message scriptMessage) workerMessageMetadata {
	return workerMessageMetadata{
		URL: message.URL, Method: message.Method,
		Headers:    map[string][]string(message.Headers),
		Trailers:   map[string][]string(message.Trailers),
		StatusCode: message.StatusCode,
	}
}

func (message workerMessageMetadata) scriptMessage(body []byte) scriptMessage {
	return scriptMessage{
		URL: message.URL, Method: message.Method,
		Headers: http.Header(message.Headers), Trailers: http.Header(message.Trailers),
		Body: body, StatusCode: message.StatusCode,
	}
}

func workerResultFrom(result scriptResult) workerResultMetadata {
	return workerResultMetadata{
		URL: result.URL, Headers: map[string][]string(result.Headers),
		Trailers: map[string][]string(result.Trailers), StatusCode: result.StatusCode,
		Synthetic: result.Synthetic, Abort: result.Abort,
		ChangedURL: result.ChangedURL, ChangedBody: result.ChangedBody,
		ChangedHeaders: result.ChangedHeaders, ChangedTrailers: result.ChangedTrailers,
		ChangedStatus: result.ChangedStatus,
	}
}

func (result workerResultMetadata) scriptResult(body []byte) scriptResult {
	return scriptResult{
		URL: result.URL, Headers: http.Header(result.Headers),
		Trailers: http.Header(result.Trailers), Body: body, StatusCode: result.StatusCode,
		Synthetic: result.Synthetic, Abort: result.Abort,
		ChangedURL: result.ChangedURL, ChangedBody: result.ChangedBody,
		ChangedHeaders: result.ChangedHeaders, ChangedTrailers: result.ChangedTrailers,
		ChangedStatus: result.ChangedStatus,
	}
}

func workerError(frame workerFrame) error {
	if len(frame.Blob1)+len(frame.Blob2) != 0 {
		return fmt.Errorf("%w: worker error frame has blobs", errWorkerProtocol)
	}
	var metadata workerErrorMetadata
	if err := unmarshalWorkerMetadata(frame.Metadata, &metadata); err != nil {
		return err
	}
	if metadata.Code != "operation_failed" {
		return fmt.Errorf("%w: worker returned an unknown error code", errWorkerProtocol)
	}
	if metadata.Message == "" || len(metadata.Message) > maxEngineLogMessageBytes {
		return fmt.Errorf("%w: worker returned an invalid error", errWorkerProtocol)
	}
	return errors.New(metadata.Message)
}
