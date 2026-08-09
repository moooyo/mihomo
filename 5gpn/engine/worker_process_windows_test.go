//go:build windows

package engine

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateWorkerResumeCount(t *testing.T) {
	if err := validateWorkerResumeCount(1); err != nil {
		t.Fatalf("single suspension rejected: %v", err)
	}
	for _, count := range []uint32{0, 2, ^uint32(0)} {
		if err := validateWorkerResumeCount(count); err == nil {
			t.Fatalf("suspend count %d accepted", count)
		}
	}
}

func TestWorkerJobListIsLeafThenAggregate(t *testing.T) {
	jobs := workerJobList(windows.Handle(11), windows.Handle(22))
	if len(jobs) != 2 || jobs[0] != windows.Handle(11) || jobs[1] != windows.Handle(22) {
		t.Fatalf("job order = %v, want leaf then aggregate", jobs)
	}
}

func TestWorkerIsolationThirdStartWaitsAndCancels(t *testing.T) {
	isolation := &workerIsolation{
		slots: make(chan struct{}, 2), closedCh: make(chan struct{}),
	}
	if err := isolation.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := isolation.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- isolation.acquire(ctx) }()
	select {
	case err := <-result:
		t.Fatalf("third admission returned before cancellation: %v", err)
	default:
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("third admission error = %v, want context cancellation", err)
	}
	isolation.release()
	if err := isolation.acquire(context.Background()); err != nil {
		t.Fatalf("admission after release: %v", err)
	}
}
