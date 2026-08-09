package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

func TestWorkerStderrDrainJoinsAndBoundsOutput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	buffer, join := startWorkerStderrDrain(reader)
	payload := bytes.Repeat([]byte("x"), workerStderrLimit+1024)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	join()
	if got := len(buffer.String()); got != workerStderrLimit {
		t.Fatalf("retained stderr = %d bytes, want %d", got, workerStderrLimit)
	}
}

func TestWorkerRPCSealRejectsLateCallback(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	client := &workerRPCClient{
		ctx: ctx, cancel: cancel, pending: make(map[uint64]workerPendingCall), done: make(chan struct{}),
	}
	if err := client.sealAndWait(context.Background()); err != nil {
		t.Fatalf("seal empty client: %v", err)
	}
	if _, err := client.call(context.Background(), workerFrame{Kind: workerFrameKindLog}, workerFrameKindLogAck); !errors.Is(err, errWorkerRPCSealed) {
		t.Fatalf("late callback error = %v, want sealed", err)
	}
	if len(client.pending) != 0 {
		t.Fatalf("late callback registered pending state: %v", client.pending)
	}
}

func TestWorkerParentNetworkCallbackBudget(t *testing.T) {
	metadata, err := marshalWorkerMetadata(workerNetworkRequestMetadata{
		URL: "not-a-url", Method: "GET", Headers: map[string][]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := workerFrame{Kind: workerFrameKindNetworkRequest, ID: 2, Metadata: metadata}
	session := &workerParentSession{
		module:  Module{ID: "test.worker", Network: true},
		network: &moduleNetworkRequester{},
	}
	var output bytes.Buffer
	if err := session.reserveNetworkCallback(); err != nil {
		t.Fatal(err)
	}
	if err := session.handleNetwork(context.Background(), newWorkerFrameWriter(&output), frame); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if session.networkCalls != 1 {
		t.Fatalf("network calls = %d, want 1", session.networkCalls)
	}

	for session.networkCalls < maxModuleNetworkCallsPerAction {
		if err := session.reserveNetworkCallback(); err != nil {
			t.Fatal(err)
		}
	}
	if err := session.reserveNetworkCallback(); !errors.Is(err, errWorkerProtocol) {
		t.Fatalf("callback above limit error = %v, want protocol error", err)
	}
}

func TestWorkerControllerCapacityFailsFast(t *testing.T) {
	controller := &workerController{slots: make(chan struct{}, 2)}
	if err := controller.acquire(); err != nil {
		t.Fatal(err)
	}
	if err := controller.acquire(); err != nil {
		t.Fatal(err)
	}
	if err := controller.acquire(); !errors.Is(err, ErrWorkerCapacity) {
		t.Fatalf("third acquire = %v, want capacity error", err)
	}
	controller.release()
	if err := controller.acquire(); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}

func TestValidateWorkerResultDistrustsTerminalFlags(t *testing.T) {
	rule := ScriptRule{Phase: "response", MaxBodyBytes: 1024}
	for name, result := range map[string]scriptResult{
		"status above HTTP range": {ChangedStatus: true, StatusCode: 700},
		"response URL mutation":   {ChangedURL: true, URL: "https://example.com/"},
		"unflagged body":          {Body: []byte("hidden")},
		"response synthetic":      {Synthetic: true},
		"case-duplicate headers": {
			ChangedHeaders: true,
			Headers:        map[string][]string{"X-Test": {"a"}, "x-test": {"b"}},
		},
		"header line break": {
			ChangedHeaders: true,
			Headers:        map[string][]string{"X-Test": {"a\r\nb"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateWorkerResult(rule, &result); !errors.Is(err, errWorkerProtocol) {
				t.Fatalf("error = %v, want protocol error", err)
			}
		})
	}
}
