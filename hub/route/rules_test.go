package route

import (
	"strings"
	"testing"

	"github.com/metacubex/http/httptest"
)

func TestDisableRulesRejectsInvalidAtomicPatch(t *testing.T) {
	request := httptest.NewRequest("PATCH", "/rules/disable", strings.NewReader(`{"999999":true}`))
	response := httptest.NewRecorder()
	disableRules(response, request)
	if response.Code < 400 {
		t.Fatalf("invalid rule disable patch returned HTTP %d", response.Code)
	}
}
