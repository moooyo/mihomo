package fivegpn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

type scriptedCertificateRunner struct {
	started chan certificateHelperSpec
	results chan error
}

func (r *scriptedCertificateRunner) Run(ctx context.Context, spec certificateHelperSpec) error {
	r.started <- spec
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-r.results:
		return err
	}
}

type recordingCertificateRunner struct {
	started chan certificateHelperSpec
	release chan struct{}

	mu        sync.Mutex
	active    int
	maxActive int
}

type cancellationStuckCertificateRunner struct {
	started chan struct{}
}

type cancellationCleanupErrorCertificateRunner struct {
	started chan struct{}
}

type recurringInterceptCertificateRunner struct {
	notifyIntercept func()
	publicRuns      chan struct{}
}

func (r *cancellationStuckCertificateRunner) Run(ctx context.Context, _ certificateHelperSpec) error {
	close(r.started)
	<-ctx.Done()
	return errCertificateHelperGroupStuck
}

func (r *cancellationCleanupErrorCertificateRunner) Run(ctx context.Context, _ certificateHelperSpec) error {
	close(r.started)
	<-ctx.Done()
	return errors.Join(ctx.Err(), errCertificateHelperCleanup)
}

func (r *recurringInterceptCertificateRunner) Run(ctx context.Context, spec certificateHelperSpec) error {
	if spec.Path == containerInterceptCertificateHelper && r.notifyIntercept != nil {
		r.notifyIntercept()
	}
	if spec.Path == containerPublicCertificateHelper {
		select {
		case r.publicRuns <- struct{}{}:
		default:
		}
	}
	timer := time.NewTimer(2 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func newRecordingCertificateRunner() *recordingCertificateRunner {
	return &recordingCertificateRunner{
		started: make(chan certificateHelperSpec, 16),
		release: make(chan struct{}, 16),
	}
}

func (r *recordingCertificateRunner) Run(ctx context.Context, spec certificateHelperSpec) error {
	r.mu.Lock()
	r.active++
	if r.active > r.maxActive {
		r.maxActive = r.active
	}
	r.mu.Unlock()
	r.started <- spec
	select {
	case <-ctx.Done():
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
		return ctx.Err()
	case <-r.release:
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
		return nil
	}
}

func waitCertificateHelper(t *testing.T, runner *recordingCertificateRunner) certificateHelperSpec {
	t.Helper()
	select {
	case spec := <-runner.started:
		return spec
	case <-time.After(time.Second):
		t.Fatal("certificate helper did not start")
		return certificateHelperSpec{}
	}
}

func TestCertificateManagerSerializesAndCoalescesReconcile(t *testing.T) {
	runner := newRecordingCertificateRunner()
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, dailyInterval: time.Hour, dailyJitter: func() time.Duration { return 0 },
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	first := waitCertificateHelper(t, runner)
	if first.Path != containerInterceptCertificateHelper || !slices.Equal(first.Args, []string{"reconcile"}) {
		t.Fatalf("first helper = %s %v, want interception reconcile", first.Path, first.Args)
	}
	if !slices.Equal(first.Environment, containerCertificateHelperEnvironment) {
		t.Fatalf("helper environment = %q, want fixed minimal environment %q", first.Environment, containerCertificateHelperEnvironment)
	}

	// Several request publications while the first signer is running describe
	// only one latest durable file. Public renewal was already pending, so fair
	// round-robin scheduling must run it before the coalesced follow-up signer.
	manager.NotifyIntercept()
	manager.NotifyIntercept()
	runner.release <- struct{}{}
	second := waitCertificateHelper(t, runner)
	if second.Path != containerPublicCertificateHelper {
		t.Fatalf("second helper = %s, want fair public renewal", second.Path)
	}
	manager.NotifyIntercept()
	runner.release <- struct{}{}
	third := waitCertificateHelper(t, runner)
	if third.Path != containerInterceptCertificateHelper || !slices.Equal(third.Args, []string{"reconcile"}) {
		t.Fatalf("third helper = %s %v, want coalesced interception reconcile", third.Path, third.Args)
	}
	runner.release <- struct{}{}

	runner.mu.Lock()
	maxActive := runner.maxActive
	runner.mu.Unlock()
	if maxActive != 1 {
		t.Fatalf("maximum concurrent helpers = %d, want 1", maxActive)
	}
}

func TestCertificateManagerCloseCancelsAndWaitsForActiveHelper(t *testing.T) {
	runner := newRecordingCertificateRunner()
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, dailyInterval: time.Hour, dailyJitter: func() time.Duration { return 0 },
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	_ = waitCertificateHelper(t, runner)
	closed := make(chan error, 1)
	go func() {
		closed <- manager.Close()
	}()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("normal cancellation Close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wait for the active helper to observe cancellation")
	}
	select {
	case <-runner.started:
		t.Fatal("a second helper started after Close")
	default:
	}
	if err := manager.Start(); err == nil {
		t.Fatal("an already-started manager restarted after Close")
	}
}

func TestCertificateManagerCloseReportsUnreapableHelperGroup(t *testing.T) {
	runner := &cancellationStuckCertificateRunner{started: make(chan struct{})}
	fatal := make(chan error, 1)
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, onFatal: func(err error) { fatal <- err },
		dailyInterval: time.Hour, dailyJitter: func() time.Duration { return 0 },
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("certificate helper did not start")
	}

	closeErr := manager.Close()
	if !errors.Is(closeErr, errCertificateHelperGroupStuck) {
		t.Fatalf("Close error = %v, want stuck helper group", closeErr)
	}
	select {
	case fatalErr := <-fatal:
		if !errors.Is(fatalErr, errCertificateHelperGroupStuck) {
			t.Fatalf("fatal error = %v, want stuck helper group", fatalErr)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown-time stuck helper group was not escalated")
	}
}

func TestCertificateManagerCloseReportsHelperCleanupFailure(t *testing.T) {
	runner := &cancellationCleanupErrorCertificateRunner{started: make(chan struct{})}
	fatal := make(chan error, 1)
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, onFatal: func(err error) { fatal <- err },
		dailyInterval: time.Hour, dailyJitter: func() time.Duration { return 0 },
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("certificate helper did not start")
	}

	closeErr := manager.Close()
	if !errors.Is(closeErr, errCertificateHelperCleanup) {
		t.Fatalf("Close error = %v, want helper cleanup failure", closeErr)
	}
	select {
	case fatalErr := <-fatal:
		if !errors.Is(fatalErr, errCertificateHelperCleanup) {
			t.Fatalf("fatal error = %v, want helper cleanup failure", fatalErr)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown-time helper cleanup failure was not escalated")
	}
}

func TestCertificateManagerDailyDelayIncludesInjectedJitter(t *testing.T) {
	manager := &certificateManager{
		dailyInterval: 24 * time.Hour,
		dailyJitter:   func() time.Duration { return 37 * time.Minute },
	}
	if got, want := manager.nextDailyDelay(), 24*time.Hour+37*time.Minute; got != want {
		t.Fatalf("daily delay = %s, want %s", got, want)
	}
}

func TestCertificateManagerDailyRenewalIsNotStarvedByContinuousInterceptWork(t *testing.T) {
	runner := &recurringInterceptCertificateRunner{publicRuns: make(chan struct{}, 4)}
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, dailyInterval: 20 * time.Millisecond,
		dailyJitter: func() time.Duration { return 0 },
	})
	runner.notifyIntercept = manager.NotifyIntercept
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	for run := 1; run <= 2; run++ {
		select {
		case <-runner.publicRuns:
		case <-time.After(time.Second):
			t.Fatalf("public certificate helper run %d was starved", run)
		}
	}
}

func TestCertificateManagerCanCloseBeforeStart(t *testing.T) {
	manager := newCertificateManager(certificateManagerOptions{
		runner: newRecordingCertificateRunner(), dailyInterval: time.Hour,
		dailyJitter: func() time.Duration { return 0 },
	})
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(); err == nil {
		t.Fatal("a closed certificate manager restarted")
	}
}

func TestContainerCertificateHelperValidationRejectsMutableOrSymlinkPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := certificateHelperSpec{Name: "test", Path: path}
	if err := validateContainerCertificateHelper(spec); err != nil {
		t.Fatalf("valid helper rejected: %v", err)
	}
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := validateContainerCertificateHelper(spec); err == nil {
		t.Fatal("group-writable helper was accepted")
	}
	link := filepath.Join(dir, "helper-link")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	spec.Path = link
	if err := validateContainerCertificateHelper(spec); err == nil {
		t.Fatal("symlink helper was accepted")
	}
}

func TestCertificateManagerRetriesFailureWithoutBlockingOtherJob(t *testing.T) {
	runner := &scriptedCertificateRunner{
		started: make(chan certificateHelperSpec, 4),
		results: make(chan error, 4),
	}
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, dailyInterval: time.Hour, dailyJitter: func() time.Duration { return 0 },
		retryMinimum: 10 * time.Millisecond, retryMaximum: 20 * time.Millisecond,
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	if first := <-runner.started; first.Path != containerInterceptCertificateHelper {
		t.Fatalf("first helper = %s, want interception", first.Path)
	}
	runner.results <- errors.New("signer failed")
	if second := <-runner.started; second.Path != containerPublicCertificateHelper {
		t.Fatalf("second helper = %s, want pending public renewal", second.Path)
	}
	runner.results <- nil
	select {
	case retry := <-runner.started:
		if retry.Path != containerInterceptCertificateHelper {
			t.Fatalf("retry helper = %s, want interception", retry.Path)
		}
		runner.results <- nil
	case <-time.After(time.Second):
		t.Fatal("failed interception helper was not retried")
	}
}

func TestCertificateManagerNotificationsCannotBypassRetryNotBefore(t *testing.T) {
	runner := &scriptedCertificateRunner{
		started: make(chan certificateHelperSpec, 8),
		results: make(chan error, 8),
	}
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, dailyInterval: time.Hour, dailyJitter: func() time.Duration { return 0 },
		retryMinimum: 500 * time.Millisecond, retryMaximum: 500 * time.Millisecond,
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	if first := <-runner.started; first.Path != containerInterceptCertificateHelper {
		t.Fatalf("first helper = %s, want interception", first.Path)
	}
	runner.results <- errors.New("signer failed")
	if second := <-runner.started; second.Path != containerPublicCertificateHelper {
		t.Fatalf("second helper = %s, want public", second.Path)
	}
	runner.results <- nil
	for range 32 {
		manager.NotifyIntercept()
	}
	select {
	case early := <-runner.started:
		t.Fatalf("notification bypassed retry not-before with %s", early.Path)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case retry := <-runner.started:
		if retry.Path != containerInterceptCertificateHelper {
			t.Fatalf("retry helper = %s, want interception", retry.Path)
		}
		runner.results <- nil
	case <-time.After(2 * time.Second):
		t.Fatal("interception helper did not run after retry not-before")
	}
}

func TestCertificateManagerEscalatesUnreapableHelperGroup(t *testing.T) {
	runner := &scriptedCertificateRunner{
		started: make(chan certificateHelperSpec, 4),
		results: make(chan error, 4),
	}
	fatal := make(chan error, 1)
	manager := newCertificateManager(certificateManagerOptions{
		runner: runner, onFatal: func(err error) { fatal <- err },
		dailyInterval: time.Hour, dailyJitter: func() time.Duration { return 0 },
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	<-runner.started
	runner.results <- errCertificateHelperGroupStuck
	select {
	case err := <-fatal:
		if !errors.Is(err, errCertificateHelperGroupStuck) {
			t.Fatalf("fatal error = %v, want stuck helper group", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stuck helper group was not escalated to the process owner")
	}
	select {
	case next := <-runner.started:
		t.Fatalf("manager started %s after an unreapable helper group", next.Path)
	case <-time.After(50 * time.Millisecond):
	}
}
