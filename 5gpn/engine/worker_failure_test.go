package engine

import (
	"context"
	"strings"
	"testing"
)

func TestWorkerGuestFailureDoesNotPoisonNextAction(t *testing.T) {
	controller, err := newWorkerController()
	if err != nil {
		t.Fatalf("worker controller: %v", err)
	}
	defer controller.Close()
	runtimeState := newScriptRuntimeWithWorker(controller, nil)
	module := Module{ID: "test.failure"}
	request := scriptMessage{URL: "https://failure.example/", Method: "GET"}

	recursive := `function transform(context) { return transform(context); }`
	recursiveRule := ScriptRule{
		ID: "recursive", Phase: "request", BodyMode: "none",
		ScriptBody: recursive, ScriptDigest: digestText(recursive),
		TimeoutMS: 10000, MaxBodyBytes: 1024,
	}
	if _, err := runtimeState.execute(context.Background(), Config{}, nil, module, recursiveRule, request, nil); err == nil {
		t.Fatal("recursive guest action succeeded")
	}

	healthy := `function transform() { return {}; }`
	healthyRule := recursiveRule
	healthyRule.ID = "healthy"
	healthyRule.ScriptBody = healthy
	healthyRule.ScriptDigest = digestText(healthy)
	result, err := runtimeState.execute(context.Background(), Config{}, nil, module, healthyRule, request, nil)
	if err != nil {
		t.Fatalf("healthy action after guest failure: %v", err)
	}
	if result.Abort || result.Synthetic || result.ChangedBody || strings.TrimSpace(result.URL) != "" {
		t.Fatalf("unexpected healthy result: %+v", result)
	}
}
