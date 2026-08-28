package engine

import (
	"io"
	"strings"
	"testing"

	"github.com/metacubex/http"
)

type discardResponseWriter struct {
	header    http.Header
	committed http.Header
}

func (w *discardResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *discardResponseWriter) Write(body []byte) (int, error) {
	if w.committed == nil {
		w.WriteHeader(http.StatusOK)
	}
	return len(body), nil
}

func (w *discardResponseWriter) WriteHeader(int) {
	if w.committed != nil {
		return
	}
	w.committed = w.Header().Clone()
}

func invokeAndRecover(handler http.Handler) (recovered any) {
	defer func() { recovered = recover() }()
	handler.ServeHTTP(&discardResponseWriter{}, &http.Request{})
	return nil
}

func TestUnexpectedHandlerPanicReportsProcessFatal(t *testing.T) {
	failures := make(chan error, 1)
	handler := failFastInterceptHandler{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("broken invariant")
		}),
		fatal: func(err error) { failures <- err },
	}

	if recovered := invokeAndRecover(handler); recovered != "broken invariant" {
		t.Fatalf("recovered panic = %#v", recovered)
	}
	select {
	case err := <-failures:
		if !strings.Contains(err.Error(), "unexpected HTTP handler panic") || !strings.Contains(err.Error(), "broken invariant") {
			t.Fatalf("fatal error = %q", err)
		}
	default:
		t.Fatal("unexpected handler panic was not reported as process-fatal")
	}
}

func TestAbortHandlerPanicRemainsRequestScoped(t *testing.T) {
	failures := make(chan error, 1)
	handler := failFastInterceptHandler{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(http.ErrAbortHandler)
		}),
		fatal: func(err error) { failures <- err },
	}

	if recovered := invokeAndRecover(handler); recovered != http.ErrAbortHandler {
		t.Fatalf("recovered panic = %#v", recovered)
	}
	select {
	case err := <-failures:
		t.Fatalf("ErrAbortHandler was reported as process-fatal: %v", err)
	default:
	}
}

func TestInterceptHandlerSeedsAltSvcClearForErrorResponses(t *testing.T) {
	writer := &discardResponseWriter{}
	handler := failFastInterceptHandler{
		next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "failed", http.StatusBadGateway)
		}),
	}
	handler.ServeHTTP(writer, &http.Request{})
	assertOnlyAltSvcClear(t, writer.committed)
}

func TestCapturedResponseWritersClearAltSvcAtFinalCommit(t *testing.T) {
	tests := []struct {
		name  string
		write func(http.ResponseWriter) error
	}{
		{
			name: "buffered action response",
			write: func(w http.ResponseWriter) error {
				return writeBufferedModuleResponse(w, http.MethodGet, http.StatusOK, http.Header{
					"alt-svc": {`h3="alternative.example:443"`},
				}, nil, []byte("body"))
			},
		},
		{
			name: "streamed origin response",
			write: func(w http.ResponseWriter) error {
				return writeStreamingProxyResponse(w, 2, http.MethodGet, &http.Response{
					StatusCode:    http.StatusOK,
					Header:        http.Header{"alt-svc": {`h3="alternative.example:443"`}},
					Body:          io.NopCloser(strings.NewReader("body")),
					ContentLength: 4,
					ProtoMajor:    2,
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &discardResponseWriter{}
			if err := test.write(writer); err != nil {
				t.Fatalf("write response: %v", err)
			}
			assertOnlyAltSvcClear(t, writer.committed)
		})
	}
}

func assertOnlyAltSvcClear(t *testing.T, header http.Header) {
	t.Helper()
	matches := 0
	for name, values := range header {
		if !strings.EqualFold(name, interceptAltSvcHeader) {
			continue
		}
		matches++
		if len(values) != 1 || values[0] != interceptAltSvcClear {
			t.Fatalf("committed %s values = %q, want [%q]", name, values, interceptAltSvcClear)
		}
	}
	if matches != 1 {
		t.Fatalf("committed Alt-Svc field count = %d, want 1", matches)
	}
}

func TestAltSvcCannotBeForwardedAsAResponseTrailer(t *testing.T) {
	input := http.Header{
		interceptAltSvcHeader: {`h3="alternative.example:443"`},
		"X-Test-Trailer":      {"present"},
	}
	trailers, err := wireTrailers(input)
	if err != nil {
		t.Fatalf("wireTrailers() error = %v", err)
	}
	if trailers.Get(interceptAltSvcHeader) != "" {
		t.Fatal("Alt-Svc survived response trailer projection")
	}
	if got := trailers.Get("X-Test-Trailer"); got != "present" {
		t.Fatalf("safe trailer = %q, want present", got)
	}
	if _, err := exportedTrailers(input); err == nil {
		t.Fatal("script output accepted Alt-Svc as a response trailer")
	}
}
