//go:build linux

package fivegpn

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func waitForHelperMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper marker %s was not created", path)
}

func writeHelperFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCertificateHelperCleanupFailureClassification(t *testing.T) {
	if err := certificateHelperCleanupFailure(nil, nil); err != nil {
		t.Fatalf("nil cleanup errors produced %v", err)
	}
	cause := errors.New("inspect process group")
	err := certificateHelperCleanupFailure(cause)
	if !errors.Is(err, errCertificateHelperCleanup) || !errors.Is(err, cause) {
		t.Fatalf("cleanup error = %v, want classification and original cause", err)
	}
}

func TestProcessCertificateHelperRunnerTerminatesAndWaitsForGroup(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	terminated := filepath.Join(dir, "terminated")
	script := writeHelperFixture(t, `
trap 'printf terminated > "$2"; exit 0' TERM
printf ready > "$1"
while :; do sleep 1; done`)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- (processCertificateHelperRunner{terminationGrace: 200 * time.Millisecond, killGrace: 200 * time.Millisecond}).Run(ctx, certificateHelperSpec{
			Name: "test", Path: script, Args: []string{ready, terminated},
			Environment: containerCertificateHelperEnvironment,
		})
	}()
	waitForHelperMarker(t, ready)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runner error = %v, want context cancellation", err)
		}
		if errors.Is(err, errCertificateHelperCleanup) {
			t.Fatalf("successful forced cleanup was misclassified: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not wait for the TERM-handled process group")
	}
	if _, err := os.Stat(terminated); err != nil {
		t.Fatalf("helper did not handle TERM: %v", err)
	}
}

func TestProcessCertificateHelperRunnerKillsGroupAfterDeadline(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	script := writeHelperFixture(t, `
trap '' TERM
printf ready > "$1"
while :; do sleep 1; done`)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- (processCertificateHelperRunner{terminationGrace: 50 * time.Millisecond, killGrace: 200 * time.Millisecond}).Run(ctx, certificateHelperSpec{
			Name: "test", Path: script, Args: []string{ready},
			Environment: containerCertificateHelperEnvironment,
		})
	}()
	waitForHelperMarker(t, ready)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runner error = %v, want context cancellation", err)
		}
		if errors.Is(err, errCertificateHelperCleanup) {
			t.Fatalf("successful forced cleanup was misclassified: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not KILL and Wait for a TERM-ignoring process group")
	}
}

func TestProcessCertificateHelperRunnerDoesNotReturnWithLiveDescendant(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	script := writeHelperFixture(t, `
(trap '' TERM; while :; do sleep 1; done) &
printf ready > "$1"
exit 0`)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- (processCertificateHelperRunner{terminationGrace: 50 * time.Millisecond, killGrace: 200 * time.Millisecond}).Run(ctx, certificateHelperSpec{
			Name: "test", Path: script, Args: []string{ready},
			Environment: containerCertificateHelperEnvironment,
		})
	}()
	waitForHelperMarker(t, ready)
	select {
	case err := <-done:
		if !errors.Is(err, errCertificateHelperDescendants) {
			t.Fatalf("runner error = %v, want descendant leak classification", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not terminate, reap, and Wait for the orphaned helper group")
	}
}

func TestReapCertificateHelperGroupIsSelective(t *testing.T) {
	leader := exec.Command("/bin/sh", "-c", "exec sleep 30")
	leader.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := leader.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := leader.Process.Pid
	member := exec.Command("/bin/sh", "-c", "exec sleep 30")
	member.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pgid}
	if err := member.Start(); err != nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		_, _ = leader.Process.Wait()
		t.Fatal(err)
	}
	other := exec.Command("/bin/sh", "-c", "exec sleep 30")
	other.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := other.Start(); err != nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		_, _ = leader.Process.Wait()
		_, _ = member.Process.Wait()
		t.Fatal(err)
	}
	groupNeedsCleanup := true
	t.Cleanup(func() {
		if groupNeedsCleanup {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		_ = other.Process.Kill()
		_, _ = other.Process.Wait()
	})

	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		empty, err := certificateHelperGroupEmpty(pgid)
		if err != nil {
			t.Fatal(err)
		}
		if empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process group remained after targeted reap")
		}
		time.Sleep(10 * time.Millisecond)
	}
	groupNeedsCleanup = false
	_ = leader.Process.Release()
	_ = member.Process.Release()
	if err := syscall.Kill(other.Process.Pid, 0); err != nil {
		t.Fatalf("reaping helper group affected unrelated process group: %v", err)
	}
}
