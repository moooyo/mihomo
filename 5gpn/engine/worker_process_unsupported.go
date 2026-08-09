//go:build !linux && !windows

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

var errWorkerIsolationClosed = errors.New("extension worker isolation is closed")

type workerProcessSpec struct {
	Executable            string
	Args, Env             []string
	Stdin, Stdout, Stderr *os.File
}

type workerProcessExit struct {
	Code  int
	OOM   bool
	State *os.ProcessState
}

// Unsupported production platforms always fail to construct this boundary.
// This implementation is reachable only in a linked Go test binary and keeps
// trusted fixtures in a separate process so macOS CI exercises the protocol.
type workerIsolation struct {
	mu         sync.Mutex
	executable string
	closed     bool
	slots      chan struct{}
	processes  map[*workerProcess]struct{}
}

type workerProcess struct {
	isolation *workerIsolation
	cmd       *exec.Cmd
	waitOnce  sync.Once
	waitDone  chan struct{}
	exit      workerProcessExit
	waitErr   error
}

func newWorkerIsolation(_ uint64, _ uint64, maxWorkers uint32) (*workerIsolation, error) {
	if !workerTestBinary() {
		return nil, errors.New("extension worker hard isolation is unsupported on this platform")
	}
	if maxWorkers == 0 {
		return nil, errors.New("extension worker concurrency limit must be positive")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &workerIsolation{
		executable: executable,
		slots:      make(chan struct{}, int(maxWorkers)),
		processes:  make(map[*workerProcess]struct{}),
	}, nil
}

func (isolation *workerIsolation) Start(ctx context.Context, spec workerProcessSpec) (*workerProcess, error) {
	if isolation == nil || ctx == nil {
		return nil, errors.New("start extension worker: invalid test isolation")
	}
	if spec.Stdin == nil || spec.Stdout == nil || spec.Stderr == nil {
		return nil, errors.New("start extension worker: stdio files are required")
	}
	if err := sameUnsupportedWorkerExecutable(spec.Executable, isolation.executable); err != nil {
		return nil, err
	}
	select {
	case isolation.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := true
	defer func() {
		if release {
			<-isolation.slots
		}
	}()
	isolation.mu.Lock()
	if isolation.closed {
		isolation.mu.Unlock()
		return nil, errWorkerIsolationClosed
	}
	cmd := exec.CommandContext(ctx, spec.Executable, spec.Args...)
	cmd.Env = append([]string(nil), spec.Env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Stdin, spec.Stdout, spec.Stderr
	process := &workerProcess{isolation: isolation, cmd: cmd, waitDone: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		isolation.mu.Unlock()
		return nil, err
	}
	isolation.processes[process] = struct{}{}
	isolation.mu.Unlock()
	release = false
	return process, nil
}

func (isolation *workerIsolation) Close() error {
	if isolation == nil {
		return nil
	}
	isolation.mu.Lock()
	if isolation.closed {
		isolation.mu.Unlock()
		return nil
	}
	isolation.closed = true
	processes := make([]*workerProcess, 0, len(isolation.processes))
	for process := range isolation.processes {
		processes = append(processes, process)
	}
	isolation.mu.Unlock()
	var joined error
	for _, process := range processes {
		joined = errors.Join(joined, process.Kill())
		_, _ = process.Wait()
	}
	return joined
}

func (process *workerProcess) Wait() (workerProcessExit, error) {
	process.waitOnce.Do(func() {
		defer close(process.waitDone)
		process.waitErr = process.cmd.Wait()
		process.exit.State = process.cmd.ProcessState
		process.exit.Code = -1
		if process.exit.State != nil {
			process.exit.Code = process.exit.State.ExitCode()
		}
		process.isolation.mu.Lock()
		delete(process.isolation.processes, process)
		process.isolation.mu.Unlock()
		<-process.isolation.slots
	})
	<-process.waitDone
	return process.exit, process.waitErr
}

func (process *workerProcess) Kill() error {
	select {
	case <-process.waitDone:
		return nil
	default:
	}
	if process.cmd == nil || process.cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := process.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (process *workerProcess) Close() error {
	killErr := process.Kill()
	_, _ = process.Wait()
	return killErr
}

func sameUnsupportedWorkerExecutable(requested, current string) error {
	requestedInfo, err := os.Stat(requested)
	if err != nil {
		return err
	}
	currentInfo, err := os.Stat(current)
	if err != nil {
		return err
	}
	if !requestedInfo.Mode().IsRegular() || !os.SameFile(requestedInfo, currentInfo) {
		return fmt.Errorf("start extension worker: executable is not the running test binary")
	}
	return nil
}
