package engine

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	M "github.com/metacubex/http"
)

func TestModuleActionAdmissionEnforcesGlobalAndExtensionLimits(t *testing.T) {
	admission := newModuleActionAdmission(3, 2)
	alphaOne, err := admission.acquire(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	alphaTwo, err := admission.acquire(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.acquire(context.Background(), "alpha"); !errors.Is(err, errModuleActionCapacity) {
		t.Fatalf("third alpha action error = %v, want capacity rejection", err)
	}
	betaOne, err := admission.acquire(context.Background(), "beta")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.acquire(context.Background(), "gamma"); !errors.Is(err, errModuleActionCapacity) {
		t.Fatalf("fourth global action error = %v, want capacity rejection", err)
	}

	alphaOne.release()
	alphaOne.release()
	gammaOne, err := admission.acquire(context.Background(), "gamma")
	if err != nil {
		t.Fatalf("released capacity was not reusable: %v", err)
	}
	alphaTwo.release()
	betaOne.release()
	gammaOne.release()

	admission.mu.Lock()
	defer admission.mu.Unlock()
	if admission.globalUsed != 0 || len(admission.perModuleUsed) != 0 {
		t.Fatalf("released admission = global %d modules %v", admission.globalUsed, admission.perModuleUsed)
	}
}

func TestModuleActionAdmissionRejectsCanceledContextWithoutConsumingCapacity(t *testing.T) {
	admission := newModuleActionAdmission(1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := admission.acquire(ctx, "alpha"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled acquire error = %v, want context.Canceled", err)
	}
	lease, err := admission.acquire(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("canceled acquire consumed capacity: %v", err)
	}
	lease.release()
}

func TestDeclarativeActionsDoNotConsumeGuestAdmission(t *testing.T) {
	runtime := newScriptRuntime()
	runtime.actionAdmission = newModuleActionAdmission(1, 1)
	held, err := runtime.actionAdmission.acquire(context.Background(), "example")
	if err != nil {
		t.Fatal(err)
	}
	rule := ScriptRule{ID: "reject", Phase: "request", TimeoutMS: 100, Reject: true}
	message := scriptMessage{URL: "https://example.test/", Method: "GET"}
	result, err := runtime.execute(context.Background(), Config{}, nil, Module{ID: "example"}, rule, message, nil)
	if err != nil {
		t.Fatalf("declarative action was blocked by guest capacity: %v", err)
	}
	if !result.Abort {
		t.Fatal("declarative reject action did not execute")
	}
	held.release()
	result, err = runtime.execute(context.Background(), Config{}, nil, Module{ID: "example"}, rule, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Abort {
		t.Fatal("admitted reject action did not execute")
	}
	runtime.actionAdmission.mu.Lock()
	defer runtime.actionAdmission.mu.Unlock()
	if runtime.actionAdmission.globalUsed != 0 || len(runtime.actionAdmission.perModuleUsed) != 0 {
		t.Fatalf("action lease was not released: global %d modules %v", runtime.actionAdmission.globalUsed, runtime.actionAdmission.perModuleUsed)
	}
}

func TestModuleBodyReservationCoversWireDecodedGuestAndResult(t *testing.T) {
	rules := []matchedScriptRule{{Rule: ScriptRule{
		BodyMode:     "binary",
		MaxBodyBytes: 1024,
		ScriptBody:   "function transform(context) { return {}; }",
	}}}
	request := &M.Request{
		Header:        M.Header{"Content-Encoding": []string{"gzip"}},
		Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 100))),
		ContentLength: 100,
	}
	const want = int64(100 + 1024 + 1024 + 2*1024)
	if got := moduleBodyReservation(request, rules); got != want {
		t.Fatalf("compressed request reservation = %d, want %d", got, want)
	}

	request.Header.Set("Content-Encoding", "identity")
	const identityWant = int64(100 + 100 + 2*1024)
	if got := moduleBodyReservation(request, rules); got != identityWant {
		t.Fatalf("identity request reservation = %d, want %d", got, identityWant)
	}
}

func TestModuleResponseReservationPrecedesPossibleDecompression(t *testing.T) {
	rules := []matchedScriptRule{{Rule: ScriptRule{
		BodyMode:     "text",
		MaxBodyBytes: 1024,
		ScriptBody:   "function transform(context) { return {}; }",
	}}}
	response := &M.Response{Header: make(M.Header), ContentLength: 100}
	want := int64(100) + maxModuleHTTPBody + 1024 + 2*1024
	if got := moduleResponseBodyReservation(response, rules); got != want {
		t.Fatalf("sniffable response reservation = %d, want %d", got, want)
	}
	response.Header.Set("Content-Encoding", "identity")
	identityWant := int64(100 + 100 + 2*1024)
	if got := moduleResponseBodyReservation(response, rules); got != identityWant {
		t.Fatalf("identity response reservation = %d, want %d", got, identityWant)
	}
}

func TestModuleBodyBudgetRejectsOversizeAndCanceledWait(t *testing.T) {
	budget := newModuleBodyBudget(10)
	if budget.acquire(context.Background(), 11, time.Second) {
		t.Fatal("reservation larger than the budget was admitted")
	}
	if !budget.acquire(context.Background(), 10, time.Second) {
		t.Fatal("full-size reservation was not admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() {
		result <- budget.acquire(ctx, 1, time.Second)
	}()
	cancel()
	select {
	case admitted := <-result:
		if admitted {
			t.Fatal("canceled waiter was admitted")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not wake")
	}
	budget.release(10)
	if !budget.acquire(context.Background(), 10, time.Second) {
		t.Fatal("capacity was not reusable after canceled wait and release")
	}
	budget.release(10)
}

func TestMaximalRequestAndResponseWorkingSetsFitOneExchange(t *testing.T) {
	rules := []matchedScriptRule{{Rule: ScriptRule{
		BodyMode:     "binary",
		MaxBodyBytes: maxModuleHTTPBody,
		ScriptBody:   "function transform(context) { return {}; }",
	}}}
	response := &M.Response{Header: make(M.Header), ContentLength: maxModuleHTTPBody}
	responseWorkingSet := moduleResponseBodyReservation(response, rules)
	if got := maxModuleHTTPBody + responseWorkingSet; got != maxModuleBodyBudgetBytes {
		t.Fatalf("retained request plus response working set = %d, budget = %d", got, maxModuleBodyBudgetBytes)
	}
	if maxInterceptHTTP2Streams <= 0 {
		t.Fatal("HTTP/2 stream admission is disabled")
	}
}
