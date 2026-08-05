package engine

import (
	"strings"
	"testing"

	"github.com/metacubex/http"
)

type discardResponseWriter struct {
	header http.Header
}

func (w *discardResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*discardResponseWriter) Write(body []byte) (int, error) { return len(body), nil }
func (*discardResponseWriter) WriteHeader(int)                {}

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
