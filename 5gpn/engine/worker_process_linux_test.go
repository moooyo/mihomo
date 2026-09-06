//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	testWorkerRoot       = "/test-cgroup"
	testSelfCgroup       = "/test-proc-self-cgroup"
	testWorkerPID        = 4242
	testWorkerMemory     = 512 << 20
	testAggregateMemory  = 1 << 30
	testManagerNonce     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testFirstActionNonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeWorkerCgroupWrite struct {
	path  string
	value string
}

type fakeWorkerCgroupFS struct {
	mu       sync.Mutex
	typeID   int64
	files    map[string][]byte
	dirs     map[string]bool
	writes   []fakeWorkerCgroupWrite
	removals []string
	openPath string
}

type blockingWorkerCleanupFS struct {
	*fakeWorkerCgroupFS
	actionPath string
	entered    chan struct{}
	proceed    chan struct{}
	once       sync.Once
}

func (fs *blockingWorkerCleanupFS) writeFile(path, value string) error {
	if path == filepath.Join(fs.actionPath, "cgroup.kill") {
		fs.once.Do(func() {
			close(fs.entered)
			<-fs.proceed
		})
	}
	return fs.fakeWorkerCgroupFS.writeFile(path, value)
}

func TestNewWorkerIsolationConfiguresDelegatedHierarchy(t *testing.T) {
	fs, deps := newFakeWorkerLinuxDependencies(t, nil)
	isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatalf("newWorkerIsolationWithDependencies() error = %v", err)
	}
	aggregate := filepath.Join(testWorkerRoot, "workers.4242."+testManagerNonce)
	if isolation.aggregatePath != aggregate {
		t.Fatalf("aggregate path = %q, want %q", isolation.aggregatePath, aggregate)
	}
	assertFakeCgroupValue(t, fs, testSelfCgroup, "0::/main")
	assertFakeCgroupValue(t, fs, filepath.Join(testWorkerRoot, "cgroup.procs"), "")
	assertFakeCgroupValue(t, fs, filepath.Join(testWorkerRoot, "main", "cgroup.procs"), "4242")
	assertFakeCgroupValue(t, fs, filepath.Join(testWorkerRoot, "cgroup.subtree_control"), "memory pids")
	assertFakeCgroupValue(t, fs, filepath.Join(aggregate, "memory.max"), "1073741824")
	assertFakeCgroupValue(t, fs, filepath.Join(aggregate, "memory.swap.max"), "0")
	assertFakeCgroupValue(t, fs, filepath.Join(aggregate, "memory.oom.group"), "0")
	assertFakeCgroupValue(t, fs, filepath.Join(aggregate, "pids.max"), "64")
	assertFakeCgroupValue(t, fs, filepath.Join(aggregate, "cgroup.subtree_control"), "memory pids")
	if err := isolation.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if fs.hasDir(aggregate) {
		t.Fatalf("aggregate cgroup %q remains after Close", aggregate)
	}
	second, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatalf("normalized main cgroup was not reusable: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	fs.setFile(testSelfCgroup, "0::/\n")
	fs.setFile(filepath.Join(testWorkerRoot, "cgroup.procs"), "4242\n")
	fs.setFile(filepath.Join(testWorkerRoot, "main", "cgroup.procs"), "\n")
	fs.setFile(filepath.Join(testWorkerRoot, "main", "cgroup.events"), "populated 0\nfrozen 0\n")
	restarted, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatalf("empty main cgroup was not reusable after process restart: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("restarted Close() error = %v", err)
	}
}

func TestNewWorkerIsolationRejectsInvalidDelegation(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*fakeWorkerCgroupFS)
		wantError string
	}{
		{
			name: "not pure v2",
			mutate: func(fs *fakeWorkerCgroupFS) {
				fs.typeID = 0
			},
			wantError: "pure cgroup v2",
		},
		{
			name: "wrong self cgroup",
			mutate: func(fs *fakeWorkerCgroupFS) {
				fs.setFile(testSelfCgroup, "0::/other\n")
			},
			wantError: "private delegated root or main cgroup",
		},
		{
			name: "root populated",
			mutate: func(fs *fakeWorkerCgroupFS) {
				fs.setFile(filepath.Join(testWorkerRoot, "cgroup.procs"), "7\n")
			},
			wantError: "only the main process",
		},
		{
			name: "main mismatch",
			mutate: func(fs *fakeWorkerCgroupFS) {
				fs.mu.Lock()
				fs.dirs[filepath.Join(testWorkerRoot, "main")] = true
				fs.seedCgroup(filepath.Join(testWorkerRoot, "main"))
				fs.files[filepath.Join(testWorkerRoot, "cgroup.procs")] = []byte("\n")
				fs.files[filepath.Join(testWorkerRoot, "cgroup.stat")] = []byte("nr_descendants 1\nnr_dying_descendants 0\n")
				fs.files[testSelfCgroup] = []byte("0::/main\n")
				fs.mu.Unlock()
				fs.setFile(filepath.Join(testWorkerRoot, "main", "cgroup.procs"), "7\n")
			},
			wantError: "must contain only the main process",
		},
		{
			name: "memory unavailable",
			mutate: func(fs *fakeWorkerCgroupFS) {
				fs.setFile(filepath.Join(testWorkerRoot, "cgroup.controllers"), "pids\n")
			},
			wantError: "memory controller",
		},
		{
			name: "pids unavailable",
			mutate: func(fs *fakeWorkerCgroupFS) {
				fs.setFile(filepath.Join(testWorkerRoot, "cgroup.controllers"), "memory\n")
			},
			wantError: "pids controller",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs, deps := newFakeWorkerLinuxDependencies(t, nil)
			test.mutate(fs)
			_, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestWorkerIsolationStartUsesAtomicCgroupAttachment(t *testing.T) {
	startError := errors.New("injected start failure")
	var captured *exec.Cmd
	var fs *fakeWorkerCgroupFS
	fs, deps := newFakeWorkerLinuxDependencies(t, func(cmd *exec.Cmd) error {
		captured = cmd
		action := filepath.Join(testWorkerRoot, "workers.4242."+testManagerNonce, "action."+testFirstActionNonce)
		assertFakeCgroupValue(t, fs, filepath.Join(action, "memory.max"), "536870912")
		assertFakeCgroupValue(t, fs, filepath.Join(action, "memory.swap.max"), "0")
		assertFakeCgroupValue(t, fs, filepath.Join(action, "memory.oom.group"), "1")
		assertFakeCgroupValue(t, fs, filepath.Join(action, "pids.max"), "32")
		return startError
	})
	isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatalf("newWorkerIsolationWithDependencies() error = %v", err)
	}
	defer func() {
		if closeErr := isolation.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()
	stdio := openWorkerDevNull(t)
	_, err = isolation.Start(context.Background(), workerProcessSpec{
		Executable: workerSelfExecutablePath,
		Args:       []string{ExtensionWorkerCommand},
		Env:        []string{"WORKER_TEST=1"},
		Stdin:      stdio,
		Stdout:     stdio,
		Stderr:     stdio,
	})
	if !errors.Is(err, startError) {
		t.Fatalf("Start() error = %v, want %v", err, startError)
	}
	if captured == nil {
		t.Fatal("start command was not invoked")
	}
	if captured.Path != workerSelfExecutablePath {
		t.Fatalf("command path = %q, want %q", captured.Path, workerSelfExecutablePath)
	}
	if !slices.Equal(captured.Args, []string{workerSelfExecutablePath, ExtensionWorkerCommand}) {
		t.Fatalf("command args = %#v", captured.Args)
	}
	if !slices.Equal(captured.Env, []string{"WORKER_TEST=1"}) {
		t.Fatalf("command environment = %#v", captured.Env)
	}
	if captured.SysProcAttr == nil || !captured.SysProcAttr.UseCgroupFD || captured.SysProcAttr.CgroupFD < 0 {
		t.Fatalf("SysProcAttr = %#v, want atomic cgroup fd attachment", captured.SysProcAttr)
	}
	if captured.Cancel == nil {
		t.Fatal("command cancellation does not kill the action cgroup")
	}
	for _, write := range fs.allWrites() {
		if filepath.Base(write.path) == "cgroup.procs" && write.path != filepath.Join(testWorkerRoot, "main", "cgroup.procs") {
			t.Fatalf("post-start cgroup migration write observed: %#v", write)
		}
	}
	isolation.mu.Lock()
	active := isolation.active
	isolation.mu.Unlock()
	if active != 0 {
		t.Fatalf("active reservations = %d after failed start, want 0", active)
	}
	action := filepath.Join(testWorkerRoot, "workers.4242."+testManagerNonce, "action."+testFirstActionNonce)
	if fs.hasDir(action) {
		t.Fatalf("failed action cgroup %q was not removed", action)
	}
}

func TestWorkerIsolationRejectsDifferentExecutable(t *testing.T) {
	started := false
	_, deps := newFakeWorkerLinuxDependencies(t, func(*exec.Cmd) error {
		started = true
		return nil
	})
	isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatalf("newWorkerIsolationWithDependencies() error = %v", err)
	}
	defer func() { _ = isolation.Close() }()
	other, err := os.CreateTemp(t.TempDir(), "other-executable-")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	stdio := openWorkerDevNull(t)
	_, err = isolation.Start(context.Background(), workerProcessSpec{
		Executable: other.Name(),
		Stdin:      stdio,
		Stdout:     stdio,
		Stderr:     stdio,
	})
	if err == nil || !strings.Contains(err.Error(), "not the running binary") {
		t.Fatalf("Start() error = %v, want running-binary refusal", err)
	}
	if started {
		t.Fatal("different executable reached process creation")
	}
}

func TestWorkerIsolationAttachmentFailureReleasesOnlyItsReservation(t *testing.T) {
	fs, deps := newFakeWorkerLinuxDependencies(t, nil)
	var commands []*exec.Cmd
	deps.startCommand = func(cmd *exec.Cmd) error {
		if err := startWorkerIsolationFixture(cmd); err != nil {
			return err
		}
		commands = append(commands, cmd)
		if len(commands) == 2 {
			action := filepath.Join(testWorkerRoot, "workers.4242."+testManagerNonce, "action.cccccccccccccccccccccccccccccccc")
			fs.setFile(filepath.Join(action, "cgroup.procs"), strconv.Itoa(cmd.Process.Pid)+"\n")
		}
		return nil
	}
	isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWorkerIsolationWithTimeout(t, isolation) })
	// Keep another reservation occupied so a double release cannot hide at zero.
	if err := isolation.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	spec := workerIsolationFixtureSpec(t)
	process, err := startWorkerIsolationWithTimeout(t, isolation, spec)
	if process != nil || err == nil || !strings.Contains(err.Error(), "verify atomic cgroup attachment") {
		t.Fatalf("Start() = %v, %v, want attachment refusal", process, err)
	}
	if len(commands) != 1 || commands[0].ProcessState == nil {
		t.Fatal("failed attachment did not reap its started child")
	}
	assertWorkerIsolationReservations(t, isolation, 1, 0)
	action := filepath.Join(isolation.aggregatePath, "action."+testFirstActionNonce)
	assertFakeCgroupRemovedOnce(t, fs, action)

	process, err = startWorkerIsolationWithTimeout(t, isolation, spec)
	if err != nil {
		t.Fatalf("Start() after failed attachment: %v", err)
	}
	assertWorkerIsolationReservations(t, isolation, 2, 1)
	if _, err := process.Wait(); err != nil {
		t.Fatalf("Wait() after healthy startup: %v", err)
	}
	assertWorkerIsolationReservations(t, isolation, 1, 0)
	assertFakeCgroupRemovedOnce(t, fs, process.cgroupPath)
	isolation.releaseReservation()
	assertWorkerIsolationReservations(t, isolation, 0, 0)
}

func TestWorkerIsolationCloseWaitsForStartup(t *testing.T) {
	for _, name := range []string{"before process start", "after process start", "successful startup"} {
		t.Run(name, func(t *testing.T) {
			started := name != "before process start"
			successful := name == "successful startup"
			fs, deps := newFakeWorkerLinuxDependencies(t, nil)
			action := filepath.Join(testWorkerRoot, "workers.4242."+testManagerNonce, "action."+testFirstActionNonce)
			blocked := &blockingWorkerCleanupFS{
				fakeWorkerCgroupFS: fs, actionPath: action,
				entered: make(chan struct{}), proceed: make(chan struct{}),
			}
			if !successful {
				deps.fs = blocked
			}
			startErr := errors.New("injected process start failure")
			var command *exec.Cmd
			deps.startCommand = func(cmd *exec.Cmd) error {
				if started {
					if err := startWorkerIsolationFixture(cmd); err != nil {
						return err
					}
					command = cmd
					if successful {
						fs.setFile(filepath.Join(action, "cgroup.procs"), strconv.Itoa(cmd.Process.Pid)+"\n")
						close(blocked.entered)
						<-blocked.proceed
					}
					return nil
				}
				return startErr
			}
			isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 1, deps)
			if err != nil {
				t.Fatal(err)
			}
			var unblockOnce sync.Once
			unblock := func() { unblockOnce.Do(func() { close(blocked.proceed) }) }
			defer unblock()
			spec := workerIsolationFixtureSpec(t)
			startDone := make(chan error, 1)
			go func() {
				_, err := isolation.Start(context.Background(), spec)
				startDone <- err
			}()
			select {
			case <-blocked.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("Start() did not reach the blocked startup stage")
			}
			if !isolation.mu.TryLock() {
				t.Fatal("startup holds the process registration lock")
			}
			isolation.mu.Unlock()
			closeDone := make(chan error, 1)
			go func() { closeDone <- isolation.Close() }()
			select {
			case <-isolation.closedCh:
			case <-time.After(5 * time.Second):
				t.Fatal("Close() could not stop admission during startup")
			}
			select {
			case err := <-closeDone:
				t.Fatalf("Close() returned before startup completed: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			if !fs.hasDir(isolation.aggregatePath) {
				t.Fatal("Close() removed the aggregate during startup cleanup")
			}
			unblock()
			select {
			case err := <-startDone:
				if successful {
					if err != nil {
						t.Fatalf("Start() error = %v", err)
					}
				} else if started {
					if err == nil || !strings.Contains(err.Error(), "verify atomic cgroup attachment") {
						t.Fatalf("Start() error = %v, want attachment refusal", err)
					}
				} else if !errors.Is(err, startErr) {
					t.Fatalf("Start() error = %v, want %v", err, startErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Start() did not complete")
			}
			select {
			case err := <-closeDone:
				if err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close() did not complete after startup")
			}
			if started && command.ProcessState == nil {
				t.Fatal("Close() left a started child unreaped")
			}
			assertWorkerIsolationReservations(t, isolation, 0, 0)
			assertFakeCgroupRemovedOnce(t, fs, action)
			assertFakeCgroupRemovedOnce(t, fs, isolation.aggregatePath)
			if _, err := isolation.Start(context.Background(), spec); !errors.Is(err, errWorkerIsolationClosed) {
				t.Fatalf("Start() after Close() = %v, want isolation closed", err)
			}
		})
	}
}

func TestWorkerIsolationExitFixture(t *testing.T) {
	if os.Getenv("FIVEGPN_WORKER_EXIT_FIXTURE") == "1" {
		os.Exit(0)
	}
}

func startWorkerIsolationFixture(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.UseCgroupFD {
		return errors.New("fixture start did not request atomic cgroup attachment")
	}
	// Only this injected test launcher replaces the fake cgroup descriptor.
	// The real test-binary child still exercises exec.Cmd cancellation and Wait.
	cmd.SysProcAttr = nil
	return cmd.Start()
}

func workerIsolationFixtureSpec(t *testing.T) workerProcessSpec {
	t.Helper()
	stdio := openWorkerDevNull(t)
	return workerProcessSpec{
		Executable: workerSelfExecutablePath,
		Args:       []string{"-test.run=^TestWorkerIsolationExitFixture$"},
		Env:        append(os.Environ(), "FIVEGPN_WORKER_EXIT_FIXTURE=1"),
		Stdin:      stdio, Stdout: stdio, Stderr: stdio,
	}
}

func startWorkerIsolationWithTimeout(t *testing.T, isolation *workerIsolation, spec workerProcessSpec) (*workerProcess, error) {
	t.Helper()
	type result struct {
		process *workerProcess
		err     error
	}
	done := make(chan result, 1)
	go func() {
		process, err := isolation.Start(context.Background(), spec)
		done <- result{process, err}
	}()
	select {
	case result := <-done:
		return result.process, result.err
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not return")
		return nil, nil
	}
}

func closeWorkerIsolationWithTimeout(t *testing.T, isolation *workerIsolation) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- isolation.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Close() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Close() did not return")
	}
}

func assertWorkerIsolationReservations(t *testing.T, isolation *workerIsolation, active uint32, processes int) {
	t.Helper()
	isolation.mu.Lock()
	defer isolation.mu.Unlock()
	if isolation.active != active || len(isolation.processes) != processes {
		t.Fatalf("worker reservations = %d, processes = %d; want %d, %d", isolation.active, len(isolation.processes), active, processes)
	}
}

func assertFakeCgroupRemovedOnce(t *testing.T, fs *fakeWorkerCgroupFS, path string) {
	t.Helper()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	var count int
	for _, removed := range fs.removals {
		if removed == path {
			count++
		}
	}
	if fs.dirs[path] || count != 1 {
		t.Fatalf("cgroup %q exists = %v, removal attempts = %d; want false, 1", path, fs.dirs[path], count)
	}
}

func TestVerifyWorkerCgroupAttachmentRequiresOnlyChild(t *testing.T) {
	fs, _ := newFakeWorkerLinuxDependencies(t, nil)
	path := filepath.Join(testWorkerRoot, "attachment")
	if err := fs.mkdir(path); err != nil {
		t.Fatal(err)
	}
	fs.setFile(filepath.Join(path, "cgroup.procs"), "91\n")
	if err := verifyWorkerCgroupAttachment(fs, path, 91); err != nil {
		t.Fatalf("exact child rejected: %v", err)
	}
	fs.setFile(filepath.Join(path, "cgroup.procs"), "91\n92\n")
	if err := verifyWorkerCgroupAttachment(fs, path, 91); err == nil {
		t.Fatal("additional process accepted in worker leaf")
	}
}

func TestWorkerIsolationTestModeSkipsCgroupOperations(t *testing.T) {
	startError := errors.New("test process start")
	var captured *exec.Cmd
	deps := workerLinuxDependencies{
		selfExecutable: workerSelfExecutablePath,
		startCommand: func(cmd *exec.Cmd) error {
			captured = cmd
			return startError
		},
		killProcess: func(int, syscall.Signal) error { return nil },
		sleep:       func(time.Duration) {},
		testMode:    true,
	}
	isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatalf("newWorkerIsolationWithDependencies() error = %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stdio := openWorkerDevNull(t)
	_, err = isolation.Start(context.Background(), workerProcessSpec{
		Executable: executable,
		Stdin:      stdio,
		Stdout:     stdio,
		Stderr:     stdio,
	})
	if !errors.Is(err, startError) {
		t.Fatalf("Start() error = %v, want %v", err, startError)
	}
	if captured == nil {
		t.Fatal("test-mode process creation was not attempted")
	}
	if captured.SysProcAttr != nil {
		t.Fatalf("test-mode SysProcAttr = %#v, want ordinary process", captured.SysProcAttr)
	}
	if captured.Path != executable {
		t.Fatalf("test-mode command path = %q, want %q", captured.Path, executable)
	}
	if err := isolation.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestWorkerIsolationAdmissionHonorsMaximumWorkers(t *testing.T) {
	deps := workerLinuxDependencies{
		selfExecutable: workerSelfExecutablePath,
		startCommand:   func(*exec.Cmd) error { return errors.New("not used") },
		killProcess:    func(int, syscall.Signal) error { return nil },
		sleep:          func(time.Duration) {},
		testMode:       true,
	}
	isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := isolation.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := isolation.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := isolation.acquire(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("third acquire error = %v, want context cancellation", err)
	}
	isolation.releaseReservation()
	if err := isolation.acquire(context.Background()); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	isolation.releaseReservation()
	isolation.releaseReservation()
	if err := isolation.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerMemoryEventsClassification(t *testing.T) {
	fs, _ := newFakeWorkerLinuxDependencies(t, nil)
	path := filepath.Join(testWorkerRoot, "memory.events.local")
	fs.setFile(path, "low 0\nhigh 1\nmax 2\noom 3\noom_kill 4\noom_group_kill 5\n")
	events, err := readWorkerMemoryEvents(fs, path)
	if err != nil {
		t.Fatalf("readWorkerMemoryEvents() error = %v", err)
	}
	if events.oomKill != 4 || events.oomGroupKill != 5 {
		t.Fatalf("events = %#v", events)
	}
	if !workerOOMIncreased(events, workerMemoryEvents{oomKill: 5, oomGroupKill: 5}) {
		t.Fatal("oom_kill increase was not classified")
	}
	if !workerOOMIncreased(events, workerMemoryEvents{oomKill: 4, oomGroupKill: 6}) {
		t.Fatal("oom_group_kill increase was not classified")
	}
	if workerOOMIncreased(events, events) {
		t.Fatal("unchanged OOM counters were classified")
	}
}

func TestTerminateWorkerCgroupFallsBackToFrozenPIDKill(t *testing.T) {
	fs, _ := newFakeWorkerLinuxDependencies(t, nil)
	path := filepath.Join(testWorkerRoot, "action."+testFirstActionNonce)
	if err := fs.mkdir(path); err != nil {
		t.Fatal(err)
	}
	fs.deleteFile(filepath.Join(path, "cgroup.kill"))
	fs.setFile(filepath.Join(path, "cgroup.procs"), "9001\n9002\n")
	fs.setFile(filepath.Join(path, "cgroup.events"), "populated 1\nfrozen 0\n")
	remaining := map[int]bool{9001: true, 9002: true}
	var killed []int
	err := terminateWorkerCgroup(fs, path, func(pid int, signal syscall.Signal) error {
		if signal != syscall.SIGKILL {
			t.Fatalf("signal = %v, want SIGKILL", signal)
		}
		if !remaining[pid] {
			t.Fatalf("unexpected pid %d", pid)
		}
		delete(remaining, pid)
		killed = append(killed, pid)
		var procs strings.Builder
		for _, candidate := range []int{9001, 9002} {
			if remaining[candidate] {
				procs.WriteString(strconv.Itoa(candidate))
				procs.WriteByte('\n')
			}
		}
		fs.setFile(filepath.Join(path, "cgroup.procs"), procs.String())
		if len(remaining) == 0 {
			fs.setFile(filepath.Join(path, "cgroup.events"), "populated 0\nfrozen 1\n")
		}
		return nil
	}, func(time.Duration) {})
	if err != nil {
		t.Fatalf("terminateWorkerCgroup() error = %v", err)
	}
	if !slices.Equal(killed, []int{9001, 9002}) {
		t.Fatalf("killed pids = %v", killed)
	}
	assertFakeCgroupValue(t, fs, filepath.Join(path, "cgroup.freeze"), "0")
	assertFakeCgroupValue(t, fs, filepath.Join(path, "cgroup.procs"), "")
}

func TestWorkerProcessKillFallsBackAndWaitConverges(t *testing.T) {
	fs, _ := newFakeWorkerLinuxDependencies(t, nil)
	path := filepath.Join(testWorkerRoot, "action."+testFirstActionNonce)
	if err := fs.mkdir(path); err != nil {
		t.Fatal(err)
	}
	fs.deleteFile(filepath.Join(path, "cgroup.kill"))
	fs.setFile(filepath.Join(path, "cgroup.procs"), "9001\n")
	fs.setFile(filepath.Join(path, "cgroup.events"), "populated 1\nfrozen 0\n")
	groupKillErr := errors.New("injected cgroup pid kill failure")
	isolation := &workerIsolation{
		fs:            fs,
		aggregatePath: testWorkerRoot,
		killProcess:   func(int, syscall.Signal) error { return groupKillErr },
		sleep:         func(time.Duration) {},
		slotChanged:   make(chan struct{}),
		closedCh:      make(chan struct{}),
		processes:     make(map[*workerProcess]struct{}),
	}
	fallbackCalled := false
	process := &workerProcess{
		isolation:  isolation,
		cmd:        exec.Command("not-started-worker"),
		cgroupPath: path,
		waitDone:   make(chan struct{}),
		fallbackKill: func() error {
			fallbackCalled = true
			fs.setFile(filepath.Join(path, "cgroup.procs"), "\n")
			fs.setFile(filepath.Join(path, "cgroup.events"), "populated 0\nfrozen 0\n")
			return nil
		},
	}
	isolation.active = 1
	isolation.processes[process] = struct{}{}
	if err := process.Kill(); !errors.Is(err, groupKillErr) {
		t.Fatalf("Kill() error = %v, want injected cgroup failure", err)
	}
	if !fallbackCalled {
		t.Fatal("Kill() did not invoke the direct process fallback")
	}
	waited := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		waited <- err
	}()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("Wait() did not converge after fallback kill")
	}
	if fs.hasDir(path) {
		t.Fatalf("action cgroup %q remains after Wait", path)
	}
}

func TestReadWorkerCgroupPIDsRejectsMalformedInput(t *testing.T) {
	fs, _ := newFakeWorkerLinuxDependencies(t, nil)
	path := filepath.Join(testWorkerRoot, "action."+testFirstActionNonce)
	if err := fs.mkdir(path); err != nil {
		t.Fatal(err)
	}
	fs.setFile(filepath.Join(path, "cgroup.procs"), "123\nnot-a-pid\n")
	if _, err := readWorkerCgroupPIDs(fs, path); err == nil {
		t.Fatal("readWorkerCgroupPIDs() accepted malformed input")
	}
}

func TestWorkerIsolationDelegatedCgroupIntegration(t *testing.T) {
	if os.Getenv("FIVEGPN_TEST_DELEGATED_CGROUP") != "1" {
		t.Skip("requires the production delegated cgroup namespace")
	}
	switch os.Getenv("FIVEGPN_WORKER_PROCESS_HELPER") {
	case "1":
		os.Exit(0)
	case "wait":
		var signal [1]byte
		if _, err := io.ReadFull(os.Stdin, signal[:]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	waitForExit := func(pid, options int) error {
		for {
			var info unix.Siginfo
			err := unix.Waitid(unix.P_PID, pid, &info, options, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
	}
	var commands []*exec.Cmd
	deps := workerLinuxDependencies{
		fs:             systemWorkerCgroupFS{},
		rootPath:       workerCgroupRootPath,
		selfCgroupPath: workerSelfCgroupPath,
		selfExecutable: workerSelfExecutablePath,
		pid:            os.Getpid(),
		nonce:          newWorkerCgroupNonce,
		startCommand: func(cmd *exec.Cmd) error {
			if cmd.SysProcAttr == nil || !cmd.SysProcAttr.UseCgroupFD {
				return errors.New("integration start did not request atomic cgroup attachment")
			}
			if err := cmd.Start(); err != nil {
				return err
			}
			commands = append(commands, cmd)
			if len(commands) != 1 {
				return nil
			}
			// An exited, unreaped child no longer appears in cgroup.procs. Keep
			// reaping owned by Start's failed-attachment path and its Cmd.Wait.
			if err := waitForExit(cmd.Process.Pid, unix.WEXITED|unix.WNOWAIT); err != nil {
				_ = cmd.Process.Kill()
				return errors.Join(fmt.Errorf("wait for early worker exit: %w", err), cmd.Wait())
			}
			return nil
		},
		killProcess: syscall.Kill,
		sleep:       time.Sleep,
	}
	isolation, err := newWorkerIsolationWithDependencies(testWorkerMemory, testAggregateMemory, 2, deps)
	if err != nil {
		t.Fatalf("newWorkerIsolationWithDependencies() error = %v", err)
	}
	t.Cleanup(func() { closeWorkerIsolationWithTimeout(t, isolation) })
	stdio := openWorkerDevNull(t)
	spec := workerProcessSpec{
		Executable: workerSelfExecutablePath,
		Args:       []string{"-test.run=^TestWorkerIsolationDelegatedCgroupIntegration$"},
		Env:        append(os.Environ(), "FIVEGPN_WORKER_PROCESS_HELPER=1"),
		Stdin:      stdio,
		Stdout:     stdio,
		Stderr:     stdio,
	}
	process, err := startWorkerIsolationWithTimeout(t, isolation, spec)
	if process != nil || err == nil || !strings.Contains(err.Error(), "verify atomic cgroup attachment") {
		t.Fatalf("Start() after early child exit = %v, %v, want attachment refusal", process, err)
	}
	if len(commands) != 1 || commands[0].ProcessState == nil || commands[0].ProcessState.ExitCode() != 0 {
		t.Fatal("failed attachment did not reap its exited child")
	}
	if err := waitForExit(commands[0].Process.Pid, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("waitid after failed startup = %v, want reaped child", err)
	}
	assertWorkerIsolationReservations(t, isolation, 0, 0)
	entries, err := os.ReadDir(isolation.aggregatePath)
	if err != nil {
		t.Fatalf("read aggregate after failed startup: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "action.") {
			t.Fatalf("failed startup left action cgroup %q", entry.Name())
		}
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = writer.Close()
		_ = reader.Close()
	})
	spec.Env = append(os.Environ(), "FIVEGPN_WORKER_PROCESS_HELPER=wait")
	spec.Stdin = reader
	process, err = startWorkerIsolationWithTimeout(t, isolation, spec)
	if err != nil {
		t.Fatalf("Start() after recovered attachment failure: %v", err)
	}
	assertWorkerIsolationReservations(t, isolation, 1, 1)
	// The second child stays alive until attachment verification has succeeded.
	if _, err := writer.Write([]byte{1}); err != nil {
		t.Fatalf("release healthy worker: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close healthy worker release pipe: %v", err)
	}
	exit, err := process.Wait()
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if exit.Code != 0 || exit.OOM {
		t.Fatalf("exit = %#v", exit)
	}
	assertWorkerIsolationReservations(t, isolation, 0, 0)
	if _, err := os.Stat(process.cgroupPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("healthy worker cgroup after Wait() = %v, want absent", err)
	}
}

func newFakeWorkerLinuxDependencies(t *testing.T, start func(*exec.Cmd) error) (*fakeWorkerCgroupFS, workerLinuxDependencies) {
	t.Helper()
	if start == nil {
		start = func(*exec.Cmd) error { return errors.New("unexpected process start") }
	}
	fs := &fakeWorkerCgroupFS{
		typeID:   unix.CGROUP2_SUPER_MAGIC,
		files:    make(map[string][]byte),
		dirs:     make(map[string]bool),
		openPath: t.TempDir(),
	}
	fs.dirs[testWorkerRoot] = true
	fs.setFile(testSelfCgroup, "0::/\n")
	fs.seedCgroup(testWorkerRoot)
	fs.setFile(filepath.Join(testWorkerRoot, "cgroup.procs"), "4242\n")
	nonces := []string{
		testManagerNonce,
		testFirstActionNonce,
		"cccccccccccccccccccccccccccccccc",
		"dddddddddddddddddddddddddddddddd",
	}
	nonceIndex := 0
	return fs, workerLinuxDependencies{
		fs:             fs,
		rootPath:       testWorkerRoot,
		selfCgroupPath: testSelfCgroup,
		selfExecutable: workerSelfExecutablePath,
		pid:            testWorkerPID,
		nonce: func() (string, error) {
			if nonceIndex >= len(nonces) {
				return "", errors.New("fake nonce source exhausted")
			}
			value := nonces[nonceIndex]
			nonceIndex++
			return value, nil
		},
		startCommand: start,
		killProcess:  func(int, syscall.Signal) error { return nil },
		sleep:        func(time.Duration) {},
	}
}

func (fs *fakeWorkerCgroupFS) seedCgroup(path string) {
	fs.files[filepath.Join(path, "cgroup.controllers")] = []byte("memory pids\n")
	fs.files[filepath.Join(path, "cgroup.subtree_control")] = []byte("\n")
	fs.files[filepath.Join(path, "cgroup.procs")] = []byte("\n")
	fs.files[filepath.Join(path, "cgroup.events")] = []byte("populated 0\nfrozen 0\n")
	fs.files[filepath.Join(path, "cgroup.stat")] = []byte("nr_descendants 0\nnr_dying_descendants 0\n")
	fs.files[filepath.Join(path, "cgroup.kill")] = []byte{}
	fs.files[filepath.Join(path, "cgroup.freeze")] = []byte("0\n")
	fs.files[filepath.Join(path, "memory.max")] = []byte("max\n")
	fs.files[filepath.Join(path, "memory.swap.max")] = []byte("max\n")
	fs.files[filepath.Join(path, "memory.oom.group")] = []byte("0\n")
	fs.files[filepath.Join(path, "memory.events.local")] = []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n")
	fs.files[filepath.Join(path, "pids.max")] = []byte("max\n")
}

func (fs *fakeWorkerCgroupFS) readFile(path string) ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	value, ok := fs.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}

func (fs *fakeWorkerCgroupFS) writeFile(path, value string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if _, ok := fs.files[path]; !ok {
		return os.ErrNotExist
	}
	fs.writes = append(fs.writes, fakeWorkerCgroupWrite{path: path, value: value})
	switch filepath.Base(path) {
	case "cgroup.procs":
		fs.files[path] = []byte(value)
		if filepath.Clean(filepath.Dir(path)) == filepath.Join(testWorkerRoot, "main") {
			fs.files[filepath.Join(testWorkerRoot, "cgroup.procs")] = []byte("\n")
			fs.files[testSelfCgroup] = []byte("0::/main\n")
			fs.files[filepath.Join(testWorkerRoot, "main", "cgroup.events")] = []byte("populated 1\nfrozen 0\n")
		}
	case "cgroup.subtree_control":
		current := strings.Fields(string(fs.files[path]))
		for _, command := range strings.Fields(value) {
			controller := strings.TrimPrefix(command, "+")
			if !slices.Contains(current, controller) {
				current = append(current, controller)
			}
		}
		fs.files[path] = []byte(strings.Join(current, " ") + "\n")
	case "cgroup.kill":
		fs.files[filepath.Join(filepath.Dir(path), "cgroup.events")] = []byte("populated 0\nfrozen 0\n")
	case "cgroup.freeze":
		frozen := strings.TrimSpace(value)
		eventsPath := filepath.Join(filepath.Dir(path), "cgroup.events")
		populated := "0"
		if strings.Contains(string(fs.files[eventsPath]), "populated 1") {
			populated = "1"
		}
		fs.files[path] = []byte(frozen + "\n")
		fs.files[eventsPath] = []byte("populated " + populated + "\nfrozen " + frozen + "\n")
	default:
		fs.files[path] = []byte(value)
	}
	return nil
}

func (fs *fakeWorkerCgroupFS) mkdir(path string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.dirs[path] {
		return os.ErrExist
	}
	if !fs.dirs[filepath.Dir(path)] {
		return os.ErrNotExist
	}
	fs.dirs[path] = true
	fs.seedCgroup(path)
	statPath := filepath.Join(filepath.Dir(path), "cgroup.stat")
	if body, ok := fs.files[statPath]; ok {
		count, _ := readFakeDescendants(body)
		fs.files[statPath] = []byte(fmt.Sprintf("nr_descendants %d\nnr_dying_descendants 0\n", count+1))
	}
	return nil
}

func readFakeDescendants(body []byte) (uint64, bool) {
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nr_descendants" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			return value, err == nil
		}
	}
	return 0, false
}

func (fs *fakeWorkerCgroupFS) remove(path string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.removals = append(fs.removals, path)
	if !fs.dirs[path] {
		return os.ErrNotExist
	}
	prefix := path + string(filepath.Separator)
	for directory := range fs.dirs {
		if strings.HasPrefix(directory, prefix) {
			return syscall.EBUSY
		}
	}
	delete(fs.dirs, path)
	for file := range fs.files {
		if strings.HasPrefix(file, prefix) {
			delete(fs.files, file)
		}
	}
	statPath := filepath.Join(filepath.Dir(path), "cgroup.stat")
	if body, ok := fs.files[statPath]; ok {
		count, valid := readFakeDescendants(body)
		if valid && count > 0 {
			fs.files[statPath] = []byte(fmt.Sprintf("nr_descendants %d\nnr_dying_descendants 0\n", count-1))
		}
	}
	return nil
}

func (fs *fakeWorkerCgroupFS) openDir(path string) (*os.File, error) {
	fs.mu.Lock()
	exists := fs.dirs[path]
	fs.mu.Unlock()
	if !exists {
		return nil, os.ErrNotExist
	}
	return os.Open(fs.openPath)
}

func (fs *fakeWorkerCgroupFS) statfsType(string) (int64, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.typeID, nil
}

func (fs *fakeWorkerCgroupFS) setFile(path, value string) {
	fs.mu.Lock()
	fs.files[path] = []byte(value)
	fs.mu.Unlock()
}

func (fs *fakeWorkerCgroupFS) deleteFile(path string) {
	fs.mu.Lock()
	delete(fs.files, path)
	fs.mu.Unlock()
}

func (fs *fakeWorkerCgroupFS) hasDir(path string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.dirs[path]
}

func (fs *fakeWorkerCgroupFS) allWrites() []fakeWorkerCgroupWrite {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]fakeWorkerCgroupWrite(nil), fs.writes...)
}

func assertFakeCgroupValue(t *testing.T, fs *fakeWorkerCgroupFS, path, want string) {
	t.Helper()
	value, err := fs.readFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if got := strings.TrimSpace(string(value)); got != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func openWorkerDevNull(t *testing.T) *os.File {
	t.Helper()
	file, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}
