package route

import (
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestRestartHandsManagedExitToProcessOwnerAfterFlush(t *testing.T) {
	response := httptest.NewRecorder()
	calls := 0
	SetRestartRequestHandler(func() bool {
		calls++
		if !response.Flushed {
			t.Error("process-owner callback ran before the success response was flushed")
		}
		return true
	})
	t.Cleanup(func() { SetRestartRequestHandler(nil) })

	request := httptest.NewRequest(http.MethodPost, "https://controller.invalid/restart", nil)
	restart(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if calls != 1 {
		t.Fatalf("process-owner callback calls = %d, want 1", calls)
	}
}
