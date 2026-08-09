package engine

import (
	"testing"
	"time"

	"github.com/dlclark/regexp2/v2"
	tdjs "github.com/tdewolff/parse/v2/js"
)

func TestInitializeGuestSafetyLimitsIsExplicitAndIdempotent(t *testing.T) {
	initializeGuestSafetyLimits()
	if tdjs.NestedExprLimit != maxScriptParserNesting || tdjs.NestedStmtLimit != maxScriptParserNesting {
		t.Fatal("JavaScript parser nesting limits were not restored")
	}
	if regexp2.DefaultMatchTimeout != 250*time.Millisecond {
		t.Fatal("regexp timeout was not restored")
	}
	initializeGuestSafetyLimits()
}
