package engine

import (
	"time"

	"github.com/dlclark/regexp2/v2"
	tdjs "github.com/tdewolff/parse/v2/js"
)

// initializeGuestSafetyLimits is explicit because the test-binary worker exits
// from an early package init and therefore cannot rely on source-file init
// ordering. Assignments are idempotent and run in both parent and child.
func initializeGuestSafetyLimits() {
	tdjs.NestedExprLimit = maxScriptParserNesting
	tdjs.NestedStmtLimit = maxScriptParserNesting
	regexp2.DefaultMatchTimeout = 250 * time.Millisecond
}

func init() { initializeGuestSafetyLimits() }
