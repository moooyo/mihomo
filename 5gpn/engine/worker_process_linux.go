//go:build linux

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	workerCgroupRootPath      = "/sys/fs/cgroup"
	workerSelfCgroupPath      = "/proc/self/cgroup"
	workerSelfExecutablePath  = "/proc/self/exe"
	workerPIDsPerProcess      = uint64(32)
	workerCgroupEmptyAttempts = 200
	workerCgroupEmptyDelay    = 5 * time.Millisecond
)

var errWorkerIsolationClosed = errors.New("extension worker isolation is closed")

type workerProcessSpec struct {
	Executable string
	Args       []string
	Env        []string
	Stdin      *os.File
	Stdout     *os.File
	Stderr     *os.File
}

type workerProcessExit struct {
	Code  int
	OOM   bool
	State *os.ProcessState
}

type workerIsolation struct {
	fs             workerCgroupFS
	rootPath       string
	aggregatePath  string
	selfExecutable string
	testMode       bool
	perWorkerBytes uint64
	maxWorkers     uint32
	nonce          func() (string, error)
	startCommand   func(*exec.Cmd) error
	killProcess    func(int, syscall.Signal) error
	sleep          func(time.Duration)

	mu          sync.Mutex
	closed      bool
	active      uint32
	slotChanged chan struct{}
	closedCh    chan struct{}
	processes   map[*workerProcess]struct{}

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

type workerProcess struct {
	isolation          *workerIsolation
	cmd                *exec.Cmd
	cgroupPath         string
	leafEventsBefore   workerMemoryEvents
	aggregateOOMBefore workerMemoryEvents

	waitOnce      sync.Once
	waitDone      chan struct{}
	exit          workerProcessExit
	waitErr       error
	cleanupErr    error
	descriptorErr error
	killMu        sync.Mutex
	reaped        bool
	fallbackKill  func() error
}

type workerMemoryEvents struct {
	oomKill      uint64
	oomGroupKill uint64
}

type workerCgroupEvents struct {
	populated bool
	frozen    bool
	hasFrozen bool
}

type workerCgroupFS interface {
	readFile(string) ([]byte, error)
	writeFile(string, string) error
	mkdir(string) error
	remove(string) error
	openDir(string) (*os.File, error)
	statfsType(string) (int64, error)
}

type systemWorkerCgroupFS struct{}

type workerLinuxDependencies struct {
	fs             workerCgroupFS
	rootPath       string
	selfCgroupPath string
	selfExecutable string
	pid            int
	nonce          func() (string, error)
	startCommand   func(*exec.Cmd) error
	killProcess    func(int, syscall.Signal) error
	sleep          func(time.Duration)
	testMode       bool
}

func newWorkerIsolation(perWorkerBytes, aggregateBytes uint64, maxWorkers uint32) (*workerIsolation, error) {
	return newWorkerIsolationWithDependencies(perWorkerBytes, aggregateBytes, maxWorkers, workerLinuxDependencies{
		fs:             systemWorkerCgroupFS{},
		rootPath:       workerCgroupRootPath,
		selfCgroupPath: workerSelfCgroupPath,
		selfExecutable: workerSelfExecutablePath,
		pid:            os.Getpid(),
		nonce:          newWorkerCgroupNonce,
		startCommand: func(cmd *exec.Cmd) error {
			return cmd.Start()
		},
		killProcess: syscall.Kill,
		sleep:       time.Sleep,
		testMode:    workerTestBinary(),
	})
}

func newWorkerIsolationWithDependencies(perWorkerBytes, aggregateBytes uint64, maxWorkers uint32, deps workerLinuxDependencies) (_ *workerIsolation, retErr error) {
	if perWorkerBytes == 0 {
		return nil, errors.New("extension worker memory limit must be positive")
	}
	if aggregateBytes < perWorkerBytes {
		return nil, errors.New("extension worker aggregate memory limit must cover one worker")
	}
	if maxWorkers == 0 {
		return nil, errors.New("extension worker concurrency limit must be positive")
	}
	if deps.startCommand == nil || deps.killProcess == nil || deps.sleep == nil {
		return nil, errors.New("extension worker isolation dependencies are incomplete")
	}
	if deps.selfExecutable == "" {
		return nil, errors.New("extension worker isolation paths are invalid")
	}
	if deps.testMode {
		// Package test binaries do not run in the installed systemd delegation.
		// Their trusted fixtures still run in a separate process, but do not fake
		// the production resident-memory cgroup with RLIMIT_AS: Go reserves a much
		// larger virtual address space, so that limit rejects healthy allocations.
		// Real OOM containment is exercised by the deployed cgroup acceptance.
		// This branch is unreachable in a production binary and is never a runtime
		// fallback from a failed cgroup setup.
		return &workerIsolation{
			selfExecutable: deps.selfExecutable,
			perWorkerBytes: perWorkerBytes,
			maxWorkers:     maxWorkers,
			startCommand:   deps.startCommand,
			killProcess:    deps.killProcess,
			sleep:          deps.sleep,
			testMode:       true,
			slotChanged:    make(chan struct{}),
			closedCh:       make(chan struct{}),
			processes:      make(map[*workerProcess]struct{}),
			closeDone:      make(chan struct{}),
		}, nil
	}
	if deps.fs == nil || deps.nonce == nil || deps.rootPath == "" || deps.selfCgroupPath == "" || deps.pid <= 0 {
		return nil, errors.New("extension worker isolation dependencies are incomplete")
	}
	if err := validateWorkerCgroupRoot(deps); err != nil {
		return nil, err
	}

	nonce, err := deps.nonce()
	if err != nil {
		return nil, fmt.Errorf("generate extension worker cgroup nonce: %w", err)
	}
	if !validWorkerCgroupNonce(nonce) {
		return nil, errors.New("generate extension worker cgroup nonce: invalid value")
	}
	aggregatePath := filepath.Join(deps.rootPath, "workers."+strconv.Itoa(deps.pid)+"."+nonce)
	if err := deps.fs.mkdir(aggregatePath); err != nil {
		return nil, fmt.Errorf("create extension worker aggregate cgroup: %w", err)
	}
	created := true
	defer func() {
		if retErr != nil && created {
			cleanupErr := cleanupWorkerCgroup(deps.fs, aggregatePath, deps.killProcess, deps.sleep, false)
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()

	aggregatePIDs := uint64(maxWorkers) * workerPIDsPerProcess
	if err := configureWorkerCgroup(deps.fs, aggregatePath, aggregateBytes, aggregatePIDs, false, true); err != nil {
		return nil, fmt.Errorf("configure extension worker aggregate cgroup: %w", err)
	}

	isolation := &workerIsolation{
		fs:             deps.fs,
		rootPath:       deps.rootPath,
		aggregatePath:  aggregatePath,
		selfExecutable: deps.selfExecutable,
		perWorkerBytes: perWorkerBytes,
		maxWorkers:     maxWorkers,
		nonce:          deps.nonce,
		startCommand:   deps.startCommand,
		killProcess:    deps.killProcess,
		sleep:          deps.sleep,
		testMode:       false,
		slotChanged:    make(chan struct{}),
		closedCh:       make(chan struct{}),
		processes:      make(map[*workerProcess]struct{}),
		closeDone:      make(chan struct{}),
	}
	created = false
	return isolation, nil
}

func (w *workerIsolation) Start(ctx context.Context, spec workerProcessSpec) (_ *workerProcess, retErr error) {
	if ctx == nil {
		return nil, errors.New("start extension worker: nil context")
	}
	if spec.Executable == "" {
		return nil, errors.New("start extension worker: executable is empty")
	}
	if spec.Stdin == nil || spec.Stdout == nil || spec.Stderr == nil {
		return nil, errors.New("start extension worker: stdio files are required")
	}
	if err := sameWorkerExecutable(spec.Executable, w.selfExecutable); err != nil {
		return nil, err
	}
	if err := w.acquire(ctx); err != nil {
		return nil, err
	}
	release := true
	defer func() {
		if release {
			w.releaseReservation()
		}
	}()
	if w.testMode {
		process, err := w.startTestProcess(ctx, spec)
		if err != nil {
			return nil, err
		}
		release = false
		return process, nil
	}

	nonce, err := w.nonce()
	if err != nil {
		return nil, fmt.Errorf("start extension worker: generate cgroup nonce: %w", err)
	}
	if !validWorkerCgroupNonce(nonce) {
		return nil, errors.New("start extension worker: generated cgroup nonce is invalid")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, errWorkerIsolationClosed
	}

	cgroupPath := filepath.Join(w.aggregatePath, "action."+nonce)
	if err := w.fs.mkdir(cgroupPath); err != nil {
		return nil, fmt.Errorf("start extension worker: create action cgroup: %w", err)
	}
	created := true
	defer func() {
		if created {
			retErr = errors.Join(retErr, cleanupWorkerCgroup(w.fs, cgroupPath, w.killProcess, w.sleep, false))
		}
	}()
	if err := configureWorkerCgroup(w.fs, cgroupPath, w.perWorkerBytes, workerPIDsPerProcess, true, false); err != nil {
		return nil, fmt.Errorf("start extension worker: configure action cgroup: %w", err)
	}
	leafEventsBefore, err := readWorkerMemoryEvents(w.fs, filepath.Join(cgroupPath, "memory.events.local"))
	if err != nil {
		return nil, fmt.Errorf("start extension worker: read action memory events: %w", err)
	}
	aggregateEventsBefore, err := readWorkerMemoryEvents(w.fs, filepath.Join(w.aggregatePath, "memory.events.local"))
	if err != nil {
		return nil, fmt.Errorf("start extension worker: read aggregate memory events: %w", err)
	}
	cgroupDir, err := w.fs.openDir(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("start extension worker: open action cgroup: %w", err)
	}

	cmd := exec.CommandContext(ctx, w.selfExecutable, spec.Args...)
	if spec.Env != nil {
		cmd.Env = append([]string{}, spec.Env...)
	}
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	// UseCgroupFD forces clone3(CLONE_INTO_CGROUP). A Start-then-migrate path
	// would let guest code allocate before memory.max applies and is forbidden.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroupDir.Fd()),
	}
	process := &workerProcess{
		isolation:          w,
		cmd:                cmd,
		cgroupPath:         cgroupPath,
		leafEventsBefore:   leafEventsBefore,
		aggregateOOMBefore: aggregateEventsBefore,
		waitDone:           make(chan struct{}),
	}
	cmd.Cancel = process.Kill

	startErr := w.startCommand(cmd)
	closeErr := cgroupDir.Close()
	if startErr != nil {
		return nil, errors.Join(fmt.Errorf("start extension worker with atomic cgroup attachment: %w", startErr), closeErr)
	}
	if closeErr != nil {
		process.descriptorErr = fmt.Errorf("close extension worker cgroup descriptor: %w", closeErr)
	}
	var attachmentErr error
	if cmd.Process == nil {
		attachmentErr = errors.New("atomic cgroup start returned no process")
	} else {
		attachmentErr = verifyWorkerCgroupAttachment(w.fs, cgroupPath, cmd.Process.Pid)
	}
	if attachmentErr != nil {
		killErr := process.Kill()
		_, waitErr := process.Wait()
		return nil, errors.Join(attachmentErr, killErr, waitErr)
	}

	w.processes[process] = struct{}{}
	created = false
	release = false
	return process, nil
}

func verifyWorkerCgroupAttachment(fs workerCgroupFS, path string, pid int) error {
	pids, err := readWorkerCgroupPIDs(fs, path)
	if err != nil {
		return fmt.Errorf("verify atomic cgroup attachment: %w", err)
	}
	if len(pids) != 1 || pids[0] != pid {
		return fmt.Errorf("verify atomic cgroup attachment: leaf processes %v do not equal child %d", pids, pid)
	}
	return nil
}

func (w *workerIsolation) Close() error {
	w.closeOnce.Do(func() {
		defer close(w.closeDone)

		w.mu.Lock()
		w.closed = true
		close(w.closedCh)
		processes := make([]*workerProcess, 0, len(w.processes))
		for process := range w.processes {
			processes = append(processes, process)
		}
		w.mu.Unlock()

		var errs []error
		if !w.testMode {
			if err := w.fs.writeFile(filepath.Join(w.aggregatePath, "cgroup.kill"), "1\n"); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("kill extension worker aggregate cgroup: %w", err))
			}
		}
		for _, process := range processes {
			if err := process.Kill(); err != nil {
				errs = append(errs, err)
			}
			_, _ = process.Wait()
			if process.cleanupErr != nil {
				errs = append(errs, process.cleanupErr)
			}
		}
		if !w.testMode {
			if err := cleanupWorkerCgroup(w.fs, w.aggregatePath, w.killProcess, w.sleep, false); err != nil {
				errs = append(errs, fmt.Errorf("remove extension worker aggregate cgroup: %w", err))
			}
		}
		w.closeErr = errors.Join(errs...)
	})
	<-w.closeDone
	return w.closeErr
}

func (p *workerProcess) Wait() (workerProcessExit, error) {
	p.waitOnce.Do(func() {
		defer close(p.waitDone)

		processErr := p.cmd.Wait()
		p.exit.State = p.cmd.ProcessState
		p.exit.Code = -1
		if p.exit.State != nil {
			p.exit.Code = p.exit.State.ExitCode()
		}
		if p.isolation.testMode {
			p.killMu.Lock()
			p.reaped = true
			p.killMu.Unlock()
			p.isolation.processDone(p)
			p.waitErr = errors.Join(processErr, p.descriptorErr)
			return
		}

		leafEvents, leafEventsErr := readWorkerMemoryEvents(p.isolation.fs, filepath.Join(p.cgroupPath, "memory.events.local"))
		aggregateEvents, aggregateEventsErr := readWorkerMemoryEvents(p.isolation.fs, filepath.Join(p.isolation.aggregatePath, "memory.events.local"))
		p.exit.OOM = workerOOMIncreased(p.leafEventsBefore, leafEvents) || workerOOMIncreased(p.aggregateOOMBefore, aggregateEvents)
		p.killMu.Lock()
		p.reaped = true
		p.cleanupErr = cleanupWorkerCgroup(p.isolation.fs, p.cgroupPath, p.isolation.killProcess, p.isolation.sleep, true)
		p.killMu.Unlock()
		p.isolation.processDone(p)

		if leafEventsErr != nil {
			leafEventsErr = fmt.Errorf("read extension worker action memory events after exit: %w", leafEventsErr)
		}
		if aggregateEventsErr != nil {
			aggregateEventsErr = fmt.Errorf("read extension worker aggregate memory events after exit: %w", aggregateEventsErr)
		}
		p.waitErr = errors.Join(processErr, p.descriptorErr, leafEventsErr, aggregateEventsErr, p.cleanupErr)
	})
	<-p.waitDone
	return p.exit, p.waitErr
}

func (p *workerProcess) Kill() error {
	select {
	case <-p.waitDone:
		return nil
	default:
	}
	groupErr := p.killCgroup()
	if groupErr != nil {
		if errors.Is(groupErr, os.ErrProcessDone) {
			return nil
		}
		var processErr error
		if p.fallbackKill != nil {
			processErr = p.fallbackKill()
		} else if p.cmd != nil && p.cmd.Process != nil {
			processErr = p.cmd.Process.Kill()
			if errors.Is(processErr, os.ErrProcessDone) {
				processErr = nil
			}
		}
		return errors.Join(fmt.Errorf("kill extension worker cgroup: %w", groupErr), processErr)
	}
	return nil
}

func (p *workerProcess) Close() error {
	killErr := p.Kill()
	_, _ = p.Wait()
	return errors.Join(killErr, p.cleanupErr)
}

func (p *workerProcess) killCgroup() error {
	p.killMu.Lock()
	defer p.killMu.Unlock()
	if p.isolation.testMode {
		if p.cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := p.cmd.Process.Kill()
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	}
	err := terminateWorkerCgroup(p.isolation.fs, p.cgroupPath, p.isolation.killProcess, p.isolation.sleep)
	if errors.Is(err, os.ErrNotExist) {
		if p.reaped {
			return os.ErrProcessDone
		}
		select {
		case <-p.waitDone:
			return os.ErrProcessDone
		default:
		}
	}
	return err
}

func (w *workerIsolation) startTestProcess(ctx context.Context, spec workerProcessSpec) (*workerProcess, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, errWorkerIsolationClosed
	}
	cmd := exec.CommandContext(ctx, spec.Executable, spec.Args...)
	if spec.Env != nil {
		cmd.Env = append([]string{}, spec.Env...)
	}
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	process := &workerProcess{
		isolation: w,
		cmd:       cmd,
		waitDone:  make(chan struct{}),
	}
	if err := w.startCommand(cmd); err != nil {
		return nil, fmt.Errorf("start extension worker test process: %w", err)
	}
	w.processes[process] = struct{}{}
	return process, nil
}

func (w *workerIsolation) acquire(ctx context.Context) error {
	for {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return errWorkerIsolationClosed
		}
		if w.active < w.maxWorkers {
			w.active++
			w.mu.Unlock()
			return nil
		}
		changed := w.slotChanged
		w.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.closedCh:
			return errWorkerIsolationClosed
		case <-changed:
		}
	}
}

func (w *workerIsolation) releaseReservation() {
	w.mu.Lock()
	w.releaseReservationLocked()
	w.mu.Unlock()
}

func (w *workerIsolation) releaseReservationLocked() {
	if w.active == 0 {
		return
	}
	w.active--
	close(w.slotChanged)
	w.slotChanged = make(chan struct{})
}

func (w *workerIsolation) processDone(process *workerProcess) {
	w.mu.Lock()
	if _, ok := w.processes[process]; ok {
		delete(w.processes, process)
		w.releaseReservationLocked()
	}
	w.mu.Unlock()
}

func validateWorkerCgroupRoot(deps workerLinuxDependencies) error {
	typeID, err := deps.fs.statfsType(deps.rootPath)
	if err != nil {
		return fmt.Errorf("verify extension worker cgroup filesystem: %w", err)
	}
	if typeID != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("extension workers require a pure cgroup v2 filesystem")
	}
	selfCgroup, err := deps.fs.readFile(deps.selfCgroupPath)
	if err != nil {
		return fmt.Errorf("read extension worker process cgroup: %w", err)
	}
	selfPath := strings.TrimSpace(string(selfCgroup))
	switch selfPath {
	case "0::/":
		rootPIDs, err := readWorkerCgroupPIDs(deps.fs, deps.rootPath)
		if err != nil {
			return fmt.Errorf("read initial delegated cgroup processes: %w", err)
		}
		if len(rootPIDs) != 1 || rootPIDs[0] != deps.pid {
			return errors.New("initial delegated cgroup must contain only the main process")
		}
		descendants, err := readWorkerCgroupDescendants(deps.fs, deps.rootPath)
		if err != nil {
			return err
		}
		mainPath := filepath.Join(deps.rootPath, "main")
		switch descendants {
		case 0:
			if err := deps.fs.mkdir(mainPath); err != nil {
				return fmt.Errorf("create trusted main cgroup: %w", err)
			}
		case 1:
			mainPIDs, err := readWorkerCgroupPIDs(deps.fs, mainPath)
			if err != nil || len(mainPIDs) != 0 {
				return errors.New("the sole residual delegated cgroup is not an empty trusted main cgroup")
			}
			mainDescendants, err := readWorkerCgroupDescendants(deps.fs, mainPath)
			if err != nil || mainDescendants != 0 {
				return errors.New("the residual trusted main cgroup contains descendants")
			}
			if err := deps.fs.remove(mainPath); err != nil {
				return fmt.Errorf("remove empty residual trusted main cgroup: %w", err)
			}
			if err := deps.fs.mkdir(mainPath); err != nil {
				return fmt.Errorf("recreate trusted main cgroup: %w", err)
			}
		default:
			return fmt.Errorf("initial delegated cgroup has %d unexpected descendants", descendants)
		}
		if err := deps.fs.writeFile(filepath.Join(mainPath, "cgroup.procs"), strconv.Itoa(deps.pid)+"\n"); err != nil {
			return fmt.Errorf("move trusted main process into its cgroup: %w", err)
		}
		selfCgroup, err = deps.fs.readFile(deps.selfCgroupPath)
		if err != nil {
			return fmt.Errorf("verify trusted main cgroup migration: %w", err)
		}
		if strings.TrimSpace(string(selfCgroup)) != "0::/main" {
			return errors.New("verify trusted main cgroup migration: process did not enter main")
		}
	case "0::/main":
		descendants, err := readWorkerCgroupDescendants(deps.fs, deps.rootPath)
		if err != nil {
			return err
		}
		if descendants != 1 {
			return fmt.Errorf("normalized delegated cgroup has %d descendants, want 1", descendants)
		}
	default:
		return fmt.Errorf("extension workers require the private delegated root or main cgroup, got %q", selfPath)
	}
	rootProcs, err := deps.fs.readFile(filepath.Join(deps.rootPath, "cgroup.procs"))
	if err != nil {
		return fmt.Errorf("read delegated cgroup root processes: %w", err)
	}
	if len(bytes.Fields(rootProcs)) != 0 {
		return errors.New("extension worker delegated cgroup root is not empty")
	}
	mainProcs, err := deps.fs.readFile(filepath.Join(deps.rootPath, "main", "cgroup.procs"))
	if err != nil {
		return fmt.Errorf("read extension worker main cgroup processes: %w", err)
	}
	mainPIDs, err := parseWorkerCgroupPIDs(mainProcs)
	if err != nil || len(mainPIDs) != 1 || mainPIDs[0] != deps.pid {
		return errors.New("extension worker main cgroup must contain only the main process")
	}
	controllers := []string{"memory", "pids"}
	if err := requireCgroupControllers(deps.fs, deps.rootPath, controllers); err != nil {
		return err
	}
	if err := enableCgroupControllers(deps.fs, deps.rootPath, controllers); err != nil {
		return fmt.Errorf("enable controllers for extension workers: %w", err)
	}
	return nil
}

func readWorkerCgroupDescendants(fs workerCgroupFS, path string) (uint64, error) {
	body, err := fs.readFile(filepath.Join(path, "cgroup.stat"))
	if err != nil {
		return 0, fmt.Errorf("read delegated cgroup descendants: %w", err)
	}
	found := false
	var descendants uint64
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, errors.New("delegated cgroup stat is malformed")
		}
		if fields[0] != "nr_descendants" {
			continue
		}
		if found {
			return 0, errors.New("delegated cgroup stat repeats nr_descendants")
		}
		found = true
		descendants, err = strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, errors.New("delegated cgroup descendant count is invalid")
		}
	}
	if !found {
		return 0, errors.New("delegated cgroup stat omits nr_descendants")
	}
	return descendants, nil
}

func configureWorkerCgroup(fs workerCgroupFS, path string, memoryLimit, pidsLimit uint64, oomGroup, enableChildren bool) error {
	oomGroupValue := "0"
	if oomGroup {
		oomGroupValue = "1"
	}
	controls := []struct {
		name  string
		value string
	}{
		{name: "memory.max", value: strconv.FormatUint(memoryLimit, 10)},
		{name: "memory.swap.max", value: "0"},
		{name: "memory.oom.group", value: oomGroupValue},
		{name: "pids.max", value: strconv.FormatUint(pidsLimit, 10)},
	}
	for _, control := range controls {
		controlPath := filepath.Join(path, control.name)
		if err := fs.writeFile(controlPath, control.value+"\n"); err != nil {
			return fmt.Errorf("write %s: %w", control.name, err)
		}
		value, err := fs.readFile(controlPath)
		if err != nil {
			return fmt.Errorf("verify %s: %w", control.name, err)
		}
		if strings.TrimSpace(string(value)) != control.value {
			return fmt.Errorf("verify %s: kernel reported %q", control.name, strings.TrimSpace(string(value)))
		}
	}
	if _, err := readWorkerMemoryEvents(fs, filepath.Join(path, "memory.events.local")); err != nil {
		return fmt.Errorf("verify memory events: %w", err)
	}
	if enableChildren {
		controllers := []string{"memory", "pids"}
		if err := requireCgroupControllers(fs, path, controllers); err != nil {
			return err
		}
		if err := enableCgroupControllers(fs, path, controllers); err != nil {
			return fmt.Errorf("enable child controllers: %w", err)
		}
	}
	return nil
}

func requireCgroupControllers(fs workerCgroupFS, path string, required []string) error {
	controllers, err := fs.readFile(filepath.Join(path, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup controllers: %w", err)
	}
	for _, controller := range required {
		if !containsField(controllers, controller) {
			return fmt.Errorf("extension workers require the cgroup %s controller", controller)
		}
	}
	return nil
}

func enableCgroupControllers(fs workerCgroupFS, path string, controllers []string) error {
	controlPath := filepath.Join(path, "cgroup.subtree_control")
	enabled, err := fs.readFile(controlPath)
	if err != nil {
		return err
	}
	var missing []string
	for _, controller := range controllers {
		if !containsField(enabled, controller) {
			missing = append(missing, "+"+controller)
		}
	}
	if len(missing) != 0 {
		if err := fs.writeFile(controlPath, strings.Join(missing, " ")+"\n"); err != nil {
			return err
		}
		enabled, err = fs.readFile(controlPath)
		if err != nil {
			return err
		}
	}
	for _, controller := range controllers {
		if !containsField(enabled, controller) {
			return fmt.Errorf("cgroup controller %s was not enabled", controller)
		}
	}
	return nil
}

func readWorkerMemoryEvents(fs workerCgroupFS, path string) (workerMemoryEvents, error) {
	data, err := fs.readFile(path)
	if err != nil {
		return workerMemoryEvents{}, err
	}
	values := make(map[string]uint64)
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return workerMemoryEvents{}, fmt.Errorf("memory events line %d is malformed", lineNumber+1)
		}
		if _, exists := values[fields[0]]; exists {
			return workerMemoryEvents{}, fmt.Errorf("memory events key %q is duplicated", fields[0])
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return workerMemoryEvents{}, fmt.Errorf("memory events key %q is invalid: %w", fields[0], parseErr)
		}
		values[fields[0]] = value
	}
	oomKill, ok := values["oom_kill"]
	if !ok {
		return workerMemoryEvents{}, errors.New("memory events omit oom_kill")
	}
	return workerMemoryEvents{
		oomKill:      oomKill,
		oomGroupKill: values["oom_group_kill"],
	}, nil
}

func workerOOMIncreased(before, after workerMemoryEvents) bool {
	return after.oomKill > before.oomKill || after.oomGroupKill > before.oomGroupKill
}

func terminateWorkerCgroup(fs workerCgroupFS, path string, killProcess func(int, syscall.Signal) error, sleep func(time.Duration)) (retErr error) {
	if err := fs.writeFile(filepath.Join(path, "cgroup.kill"), "1\n"); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("write cgroup.kill: %w", err)
	}

	frozen := false
	if err := fs.writeFile(filepath.Join(path, "cgroup.freeze"), "1\n"); err == nil {
		frozen = true
		defer func() {
			if frozen {
				retErr = errors.Join(retErr, fs.writeFile(filepath.Join(path, "cgroup.freeze"), "0\n"))
			}
		}()
		if err := waitWorkerCgroupFrozen(fs, path, sleep); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("freeze extension worker cgroup: %w", err)
	}

	for attempt := 0; attempt < workerCgroupEmptyAttempts; attempt++ {
		pids, err := readWorkerCgroupPIDs(fs, path)
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			return nil
		}
		var killErrs []error
		for _, pid := range pids {
			if err := killProcess(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				killErrs = append(killErrs, fmt.Errorf("kill cgroup process %d: %w", pid, err))
			}
		}
		if err := errors.Join(killErrs...); err != nil {
			return err
		}
		sleep(workerCgroupEmptyDelay)
	}
	return errors.New("extension worker cgroup processes remained after SIGKILL")
}

func waitWorkerCgroupFrozen(fs workerCgroupFS, path string, sleep func(time.Duration)) error {
	for attempt := 0; attempt < workerCgroupEmptyAttempts; attempt++ {
		events, err := readWorkerCgroupEvents(fs, path)
		if err != nil {
			return err
		}
		if !events.populated {
			return nil
		}
		if !events.hasFrozen {
			return errors.New("cgroup events omit frozen")
		}
		if events.frozen {
			return nil
		}
		sleep(workerCgroupEmptyDelay)
	}
	return errors.New("extension worker cgroup did not freeze")
}

func readWorkerCgroupPIDs(fs workerCgroupFS, path string) ([]int, error) {
	data, err := fs.readFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	return parseWorkerCgroupPIDs(data)
}

func parseWorkerCgroupPIDs(data []byte) ([]int, error) {
	fields := bytes.Fields(data)
	pids := make([]int, 0, len(fields))
	seen := make(map[int]struct{}, len(fields))
	for _, field := range fields {
		pid, parseErr := strconv.Atoi(string(field))
		if parseErr != nil || pid <= 0 {
			return nil, fmt.Errorf("cgroup process id %q is invalid", field)
		}
		if _, exists := seen[pid]; exists {
			return nil, fmt.Errorf("cgroup process id %d is duplicated", pid)
		}
		seen[pid] = struct{}{}
		pids = append(pids, pid)
	}
	return pids, nil
}

func cleanupWorkerCgroup(fs workerCgroupFS, path string, killProcess func(int, syscall.Signal) error, sleep func(time.Duration), reportDescendants bool) error {
	var errs []error
	populated, err := readWorkerCgroupPopulated(fs, path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("read cgroup population: %w", err))
	}
	if populated && reportDescendants {
		errs = append(errs, errors.New("extension worker left descendant processes behind"))
	}
	if err := terminateWorkerCgroup(fs, path, killProcess, sleep); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("kill cgroup: %w", err))
	}
	if err := waitWorkerCgroupEmpty(fs, path, sleep); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := fs.remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove cgroup: %w", err))
	}
	return errors.Join(errs...)
}

func waitWorkerCgroupEmpty(fs workerCgroupFS, path string, sleep func(time.Duration)) error {
	for attempt := 0; attempt < workerCgroupEmptyAttempts; attempt++ {
		populated, err := readWorkerCgroupPopulated(fs, path)
		if err != nil {
			return err
		}
		if !populated {
			return nil
		}
		sleep(workerCgroupEmptyDelay)
	}
	return errors.New("extension worker cgroup remained populated after kill")
}

func readWorkerCgroupPopulated(fs workerCgroupFS, path string) (bool, error) {
	events, err := readWorkerCgroupEvents(fs, path)
	return events.populated, err
}

func readWorkerCgroupEvents(fs workerCgroupFS, path string) (workerCgroupEvents, error) {
	data, err := fs.readFile(filepath.Join(path, "cgroup.events"))
	if err != nil {
		return workerCgroupEvents{}, err
	}
	events := workerCgroupEvents{}
	seenPopulated := false
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return workerCgroupEvents{}, fmt.Errorf("cgroup events line %d is malformed", lineNumber+1)
		}
		if fields[0] != "populated" && fields[0] != "frozen" {
			continue
		}
		if fields[0] == "populated" && seenPopulated {
			return workerCgroupEvents{}, errors.New("cgroup events populated key is duplicated")
		}
		if fields[0] == "frozen" && events.hasFrozen {
			return workerCgroupEvents{}, errors.New("cgroup events frozen key is duplicated")
		}
		value := false
		switch fields[1] {
		case "0":
		case "1":
			value = true
		default:
			return workerCgroupEvents{}, fmt.Errorf("cgroup events %s value %q is invalid", fields[0], fields[1])
		}
		if fields[0] == "populated" {
			seenPopulated = true
			events.populated = value
		} else {
			events.hasFrozen = true
			events.frozen = value
		}
	}
	if !seenPopulated {
		return workerCgroupEvents{}, errors.New("cgroup events omit populated")
	}
	return events, nil
}

func sameWorkerExecutable(requested, self string) error {
	requestedInfo, err := os.Stat(requested)
	if err != nil {
		return fmt.Errorf("start extension worker: stat executable: %w", err)
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		return fmt.Errorf("start extension worker: stat running executable: %w", err)
	}
	if !os.SameFile(requestedInfo, selfInfo) {
		return errors.New("start extension worker: executable is not the running binary")
	}
	return nil
}

func newWorkerCgroupNonce() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func validWorkerCgroupNonce(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func containsField(data []byte, wanted string) bool {
	for _, field := range bytes.Fields(data) {
		if string(field) == wanted {
			return true
		}
	}
	return false
}

func (systemWorkerCgroupFS) readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (systemWorkerCgroupFS) writeFile(path, value string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, value)
	return errors.Join(writeErr, file.Close())
}

func (systemWorkerCgroupFS) mkdir(path string) error {
	return os.Mkdir(path, 0o755)
}

func (systemWorkerCgroupFS) remove(path string) error {
	return os.Remove(path)
}

func (systemWorkerCgroupFS) openDir(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (systemWorkerCgroupFS) statfsType(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Type), nil
}
