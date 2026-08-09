//go:build windows

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// These attributes are available on Windows 10 and Windows Server 2016 or
	// newer. Failing to install either one is a hard isolation failure.
	procThreadAttributeJobList            = 0x0002000d
	procThreadAttributeChildProcessPolicy = 0x0002000e
	processCreationChildProcessRestricted = 0x00000001

	workerForcedExitCode = 0xe0000001

	statusNoMemory        = 0xc0000017
	statusCommitmentLimit = 0xc000012d
)

const workerForbiddenJobLimitFlags = windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK |
	windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK

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

type workerProcessExitError struct {
	code int
}

func (e *workerProcessExitError) Error() string {
	return fmt.Sprintf("extension worker exited with code %d", e.code)
}

type workerIsolation struct {
	mu sync.Mutex

	aggregateJob   windows.Handle
	perWorkerBytes uint64
	aggregateBytes uint64
	maxWorkers     uint32
	closed         bool
	slots          chan struct{}
	closedCh       chan struct{}
	closeSignal    sync.Once
}

type workerProcess struct {
	mu sync.Mutex

	process windows.Handle
	leafJob windows.Handle
	waited  bool

	waitOnce sync.Once
	waitExit workerProcessExit
	waitErr  error

	closeOnce sync.Once
	closeErr  error
	slotOnce  sync.Once
	isolation *workerIsolation
}

type jobObjectBasicProcessIDList struct {
	NumberOfAssignedProcesses uint32
	NumberOfProcessIDsInList  uint32
	ProcessIDList             [1]uintptr
}

type jobObjectLimitViolationInformation struct {
	LimitFlags                uint32
	ViolationLimitFlags       uint32
	IOReadBytes               uint64
	IOReadBytesLimit          uint64
	IOWriteBytes              uint64
	IOWriteBytesLimit         uint64
	PerJobUserTime            int64
	PerJobUserTimeLimit       int64
	JobMemory                 uint64
	JobMemoryLimit            uint64
	RateControlTolerance      uint32
	RateControlToleranceLimit uint32
}

type jobObjectLimitViolationInformation2 struct {
	LimitFlags                   uint32
	ViolationLimitFlags          uint32
	IOReadBytes                  uint64
	IOReadBytesLimit             uint64
	IOWriteBytes                 uint64
	IOWriteBytesLimit            uint64
	PerJobUserTime               int64
	PerJobUserTimeLimit          int64
	JobMemory                    uint64
	JobHighMemoryLimit           uint64
	RateControlTolerance         uint32
	RateControlToleranceLimit    uint32
	JobLowMemoryLimit            uint64
	IORateControlTolerance       uint32
	IORateControlToleranceLimit  uint32
	NetRateControlTolerance      uint32
	NetRateControlToleranceLimit uint32
}

func newWorkerIsolation(perWorkerBytes, aggregateBytes uint64, maxWorkers uint32) (*workerIsolation, error) {
	if perWorkerBytes == 0 {
		return nil, errors.New("worker per-process memory limit must be positive")
	}
	if aggregateBytes == 0 {
		return nil, errors.New("worker aggregate memory limit must be positive")
	}
	if aggregateBytes < perWorkerBytes {
		return nil, errors.New("worker aggregate memory limit must cover one worker")
	}
	if maxWorkers == 0 {
		return nil, errors.New("worker process limit must be positive")
	}
	if !workerMemoryLimitFits(perWorkerBytes) {
		return nil, fmt.Errorf("worker per-process memory limit %d does not fit SIZE_T", perWorkerBytes)
	}
	if !workerMemoryLimitFits(aggregateBytes) {
		return nil, fmt.Errorf("worker aggregate memory limit %d does not fit SIZE_T", aggregateBytes)
	}

	aggregateJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create aggregate worker job: %w", err)
	}
	configured := false
	defer func() {
		if !configured {
			_ = windows.CloseHandle(aggregateJob)
		}
	}()

	if err := configureWorkerJob(aggregateJob, 0, aggregateBytes, maxWorkers); err != nil {
		return nil, fmt.Errorf("configure aggregate worker job: %w", err)
	}
	configured = true
	return &workerIsolation{
		aggregateJob:   aggregateJob,
		perWorkerBytes: perWorkerBytes,
		aggregateBytes: aggregateBytes,
		maxWorkers:     maxWorkers,
		slots:          make(chan struct{}, int(maxWorkers)),
		closedCh:       make(chan struct{}),
	}, nil
}

func (i *workerIsolation) Start(ctx context.Context, spec workerProcessSpec) (_ *workerProcess, returnErr error) {
	if ctx == nil {
		return nil, errors.New("worker context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := i.acquire(ctx); err != nil {
		return nil, err
	}
	releaseSlot := true
	defer func() {
		if releaseSlot {
			i.release()
		}
	}()

	executable, err := verifiedWorkerExecutable(spec.Executable)
	if err != nil {
		return nil, err
	}
	applicationName, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, fmt.Errorf("encode worker executable: %w", err)
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{executable}, spec.Args...)))
	if err != nil {
		return nil, fmt.Errorf("encode worker command line: %w", err)
	}
	environment, err := workerEnvironmentBlock(spec.Env)
	if err != nil {
		return nil, err
	}
	var environmentPointer *uint16
	if environment != nil {
		environmentPointer = &environment[0]
	}

	stdio, err := duplicateWorkerStdio(spec.Stdin, spec.Stdout, spec.Stderr)
	if err != nil {
		return nil, err
	}
	stdioOwned := true
	defer func() {
		if stdioOwned {
			returnErr = errors.Join(returnErr, closeWorkerHandles(stdio))
		}
	}()

	leafJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create leaf worker job: %w", err)
	}
	leafOwned := true
	processCreated := false
	var processInfo windows.ProcessInformation
	defer func() {
		if !leafOwned {
			return
		}
		if processCreated {
			returnErr = errors.Join(returnErr, abortWindowsWorker(leafJob, processInfo.Process, processInfo.Thread))
			return
		}
		returnErr = errors.Join(returnErr, windows.CloseHandle(leafJob))
	}()

	if err := configureWorkerJob(leafJob, i.perWorkerBytes, i.perWorkerBytes, 1); err != nil {
		return nil, fmt.Errorf("configure leaf worker job: %w", err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed || i.aggregateJob == 0 {
		return nil, errWorkerIsolationClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	attributes, err := windows.NewProcThreadAttributeList(3)
	if err != nil {
		return nil, fmt.Errorf("allocate worker process attributes: %w", err)
	}
	attributesOwned := true
	defer func() {
		if attributesOwned {
			attributes.Delete()
		}
	}()

	// Windows nests jobs in the order supplied: the immediate leaf must come
	// first and its aggregate parent second.
	jobs := workerJobList(leafJob, i.aggregateJob)
	if err := attributes.Update(
		procThreadAttributeJobList,
		unsafe.Pointer(&jobs[0]),
		uintptr(len(jobs))*unsafe.Sizeof(jobs[0]),
	); err != nil {
		return nil, fmt.Errorf("install worker job list: %w", err)
	}
	childPolicy := uint32(processCreationChildProcessRestricted)
	if err := attributes.Update(
		procThreadAttributeChildProcessPolicy,
		unsafe.Pointer(&childPolicy),
		unsafe.Sizeof(childPolicy),
	); err != nil {
		return nil, fmt.Errorf("install worker child-process policy: %w", err)
	}
	if err := attributes.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&stdio[0]),
		uintptr(len(stdio))*unsafe.Sizeof(stdio[0]),
	); err != nil {
		return nil, fmt.Errorf("install worker handle allowlist: %w", err)
	}

	startupInfo := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  stdio[0],
			StdOutput: stdio[1],
			StdErr:    stdio[2],
		},
		ProcThreadAttributeList: attributes.List(),
	}
	creationFlags := uint32(
		windows.CREATE_DEFAULT_ERROR_MODE |
			windows.CREATE_NO_WINDOW |
			windows.CREATE_SUSPENDED |
			windows.CREATE_UNICODE_ENVIRONMENT |
			windows.EXTENDED_STARTUPINFO_PRESENT,
	)
	if err := windows.CreateProcess(
		applicationName,
		commandLine,
		nil,
		nil,
		true,
		creationFlags,
		environmentPointer,
		nil,
		&startupInfo.StartupInfo,
		&processInfo,
	); err != nil {
		return nil, fmt.Errorf("create isolated worker process: %w", err)
	}
	processCreated = true
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(childPolicy)
	runtime.KeepAlive(stdio)
	runtime.KeepAlive(environment)

	attributes.Delete()
	attributesOwned = false
	if err := closeWorkerHandles(stdio); err != nil {
		return nil, fmt.Errorf("close parent worker pipe handles: %w", err)
	}
	stdioOwned = false

	if err := verifyWorkerJob(i.aggregateJob, 0, i.aggregateBytes, i.maxWorkers); err != nil {
		return nil, fmt.Errorf("verify aggregate worker job: %w", err)
	}
	if err := verifyWorkerJob(leafJob, i.perWorkerBytes, i.perWorkerBytes, 1); err != nil {
		return nil, fmt.Errorf("verify leaf worker job: %w", err)
	}
	if err := verifySingleWorkerPID(leafJob, processInfo); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	previousSuspendCount, err := windows.ResumeThread(processInfo.Thread)
	if err != nil {
		return nil, fmt.Errorf("resume isolated worker process: %w", err)
	}
	if err := validateWorkerResumeCount(previousSuspendCount); err != nil {
		return nil, err
	}
	if err := windows.CloseHandle(processInfo.Thread); err != nil {
		return nil, fmt.Errorf("close worker thread handle: %w", err)
	}
	processInfo.Thread = 0
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	process := &workerProcess{
		process:   processInfo.Process,
		leafJob:   leafJob,
		isolation: i,
	}
	leafOwned = false
	releaseSlot = false
	return process, nil
}

func workerJobList(leaf, aggregate windows.Handle) []windows.Handle {
	return []windows.Handle{leaf, aggregate}
}

func (i *workerIsolation) acquire(ctx context.Context) error {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return errWorkerIsolationClosed
	}
	closedCh := i.closedCh
	i.mu.Unlock()
	select {
	case i.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-closedCh:
		return errWorkerIsolationClosed
	}
}

func (i *workerIsolation) release() {
	select {
	case <-i.slots:
	default:
	}
}

func validateWorkerResumeCount(previous uint32) error {
	if previous != 1 {
		return fmt.Errorf("resume isolated worker process: previous suspend count is %d, want 1", previous)
	}
	return nil
}

func (i *workerIsolation) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	i.closeSignal.Do(func() { close(i.closedCh) })
	job := i.aggregateJob
	i.aggregateJob = 0
	if job == 0 {
		return nil
	}
	terminateErr := windows.TerminateJobObject(job, workerForcedExitCode)
	if terminateErr != nil {
		terminateErr = fmt.Errorf("terminate aggregate worker job: %w", terminateErr)
	}
	closeErr := windows.CloseHandle(job)
	if closeErr != nil {
		closeErr = fmt.Errorf("close aggregate worker job: %w", closeErr)
	}
	return errors.Join(terminateErr, closeErr)
}

func (p *workerProcess) Wait() (workerProcessExit, error) {
	p.waitOnce.Do(func() {
		defer p.releaseSlot()
		p.mu.Lock()
		process := p.process
		job := p.leafJob
		p.mu.Unlock()
		if process == 0 {
			p.waitErr = errors.New("worker process is closed")
			return
		}

		waitResult, err := windows.WaitForSingleObject(process, 10_000)
		if err != nil {
			p.waitErr = fmt.Errorf("wait for worker process: %w", err)
			return
		}
		if waitResult != windows.WAIT_OBJECT_0 {
			p.waitErr = fmt.Errorf("wait for worker process returned status %#x", waitResult)
			return
		}
		var code uint32
		if err := windows.GetExitCodeProcess(process, &code); err != nil {
			p.waitErr = fmt.Errorf("read worker exit code: %w", err)
			return
		}
		p.waitExit.Code = int(code)
		p.mu.Lock()
		p.waited = true
		p.mu.Unlock()

		if job == 0 {
			p.waitExit.OOM = workerExitCodeIsOOM(code)
		} else {
			oom, err := workerJobOOM(job, code)
			p.waitExit.OOM = oom
			if err != nil {
				p.waitErr = err
				return
			}
		}
		if code != 0 {
			p.waitErr = &workerProcessExitError{code: int(code)}
		}
	})
	return p.waitExit, p.waitErr
}

func (p *workerProcess) releaseSlot() {
	p.slotOnce.Do(func() {
		if p.isolation != nil {
			p.isolation.release()
		}
	})
}

func (p *workerProcess) Kill() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.waited || p.leafJob == 0 {
		return nil
	}
	if err := windows.TerminateJobObject(p.leafJob, workerForcedExitCode); err != nil {
		job := p.leafJob
		p.leafJob = 0
		closeErr := windows.CloseHandle(job)
		if closeErr != nil {
			closeErr = fmt.Errorf("close worker job after termination failure: %w", closeErr)
		}
		var processErr error
		if closeErr != nil && p.process != 0 {
			processErr = windows.TerminateProcess(p.process, workerForcedExitCode)
			if processErr != nil {
				processErr = fmt.Errorf("terminate worker process fallback: %w", processErr)
			}
		}
		return errors.Join(fmt.Errorf("terminate worker job: %w", err), closeErr, processErr)
	}
	return nil
}

func (p *workerProcess) Close() error {
	p.closeOnce.Do(func() {
		killErr := p.Kill()
		_, _ = p.Wait()

		p.mu.Lock()
		process := p.process
		job := p.leafJob
		p.process = 0
		p.leafJob = 0
		p.mu.Unlock()

		var processErr, jobErr error
		if process != 0 {
			processErr = windows.CloseHandle(process)
		}
		if job != 0 {
			jobErr = windows.CloseHandle(job)
		}
		p.closeErr = errors.Join(killErr, processErr, jobErr)
	})
	return p.closeErr
}

func workerMemoryLimitFits(value uint64) bool {
	return uint64(uintptr(value)) == value
}

func configureWorkerJob(job windows.Handle, processBytes, jobBytes uint64, activeProcesses uint32) error {
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_JOB_MEMORY |
				windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
				windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			ActiveProcessLimit: activeProcesses,
		},
		JobMemoryLimit: uintptr(jobBytes),
	}
	if processBytes != 0 {
		limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		limits.ProcessMemoryLimit = uintptr(processBytes)
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		return err
	}
	return verifyWorkerJob(job, processBytes, jobBytes, activeProcesses)
}

func verifyWorkerJob(job windows.Handle, processBytes, jobBytes uint64, activeProcesses uint32) error {
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var returned uint32
	if err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
		&returned,
	); err != nil {
		return err
	}
	if returned != uint32(unsafe.Sizeof(limits)) {
		return fmt.Errorf("job limit query returned %d bytes, want %d", returned, unsafe.Sizeof(limits))
	}
	expectedFlags := uint32(
		windows.JOB_OBJECT_LIMIT_JOB_MEMORY |
			windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
			windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
	)
	if processBytes != 0 {
		expectedFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
	}
	actualFlags := limits.BasicLimitInformation.LimitFlags
	if actualFlags&workerForbiddenJobLimitFlags != 0 {
		return fmt.Errorf("job permits process breakaway with flags %#x", actualFlags)
	}
	if actualFlags != expectedFlags {
		return fmt.Errorf("job limit flags are %#x, want %#x", actualFlags, expectedFlags)
	}
	if limits.BasicLimitInformation.ActiveProcessLimit != activeProcesses {
		return fmt.Errorf("job process limit is %d, want %d", limits.BasicLimitInformation.ActiveProcessLimit, activeProcesses)
	}
	if uint64(limits.ProcessMemoryLimit) != processBytes {
		return fmt.Errorf("job process memory limit is %d, want %d", limits.ProcessMemoryLimit, processBytes)
	}
	if uint64(limits.JobMemoryLimit) != jobBytes {
		return fmt.Errorf("job memory limit is %d, want %d", limits.JobMemoryLimit, jobBytes)
	}
	return nil
}

func verifySingleWorkerPID(job windows.Handle, processInfo windows.ProcessInformation) error {
	var processIDs jobObjectBasicProcessIDList
	var returned uint32
	if err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&processIDs)),
		uint32(unsafe.Sizeof(processIDs)),
		&returned,
	); err != nil {
		return fmt.Errorf("read leaf worker job process list: %w", err)
	}
	if returned != uint32(unsafe.Sizeof(processIDs)) {
		return fmt.Errorf("leaf worker process query returned %d bytes, want %d", returned, unsafe.Sizeof(processIDs))
	}
	if processIDs.NumberOfAssignedProcesses != 1 || processIDs.NumberOfProcessIDsInList != 1 {
		return fmt.Errorf(
			"leaf worker job has %d assigned processes and %d listed process IDs",
			processIDs.NumberOfAssignedProcesses,
			processIDs.NumberOfProcessIDsInList,
		)
	}
	actualProcessID, err := windows.GetProcessId(processInfo.Process)
	if err != nil {
		return fmt.Errorf("read worker process ID: %w", err)
	}
	if actualProcessID != processInfo.ProcessId || processIDs.ProcessIDList[0] != uintptr(processInfo.ProcessId) {
		return fmt.Errorf(
			"leaf worker PID mismatch: job=%d handle=%d create=%d",
			processIDs.ProcessIDList[0],
			actualProcessID,
			processInfo.ProcessId,
		)
	}
	return nil
}

func verifiedWorkerExecutable(requested string) (string, error) {
	if requested == "" {
		return "", errors.New("worker executable is empty")
	}
	current, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find current executable: %w", err)
	}
	currentInfo, err := os.Stat(current)
	if err != nil {
		return "", fmt.Errorf("inspect current executable: %w", err)
	}
	requestedInfo, err := os.Stat(requested)
	if err != nil {
		return "", fmt.Errorf("inspect worker executable: %w", err)
	}
	if !requestedInfo.Mode().IsRegular() || !os.SameFile(currentInfo, requestedInfo) {
		return "", errors.New("worker executable is not the current binary")
	}
	return current, nil
}

func workerEnvironmentBlock(environment []string) ([]uint16, error) {
	if environment == nil {
		return nil, nil
	}
	ordered := append([]string(nil), environment...)
	for _, entry := range ordered {
		if strings.IndexByte(entry, 0) >= 0 {
			return nil, errors.New("worker environment contains NUL")
		}
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		return strings.ToUpper(workerEnvironmentKey(ordered[left])) < strings.ToUpper(workerEnvironmentKey(ordered[right]))
	})

	block := make([]uint16, 0, len(ordered)+1)
	for _, entry := range ordered {
		block = append(block, utf16.Encode([]rune(entry))...)
		block = append(block, 0)
	}
	block = append(block, 0)
	if len(block) == 1 {
		block = append(block, 0)
	}
	return block, nil
}

func workerEnvironmentKey(entry string) string {
	separator := strings.IndexByte(entry, '=')
	if separator < 0 {
		return ""
	}
	return entry[:separator]
}

func duplicateWorkerStdio(stdin, stdout, stderr *os.File) ([]windows.Handle, error) {
	files := []*os.File{stdin, stdout, stderr}
	handles := make([]windows.Handle, 0, len(files))
	currentProcess := windows.CurrentProcess()
	for _, file := range files {
		if file == nil {
			return nil, errors.Join(errors.New("worker standard handles must not be nil"), closeWorkerHandles(handles))
		}
		source := windows.Handle(file.Fd())
		if source == 0 || source == windows.InvalidHandle {
			return nil, errors.Join(errors.New("worker standard handle is invalid"), closeWorkerHandles(handles))
		}
		var duplicate windows.Handle
		if err := windows.DuplicateHandle(
			currentProcess,
			source,
			currentProcess,
			&duplicate,
			0,
			true,
			windows.DUPLICATE_SAME_ACCESS,
		); err != nil {
			return nil, errors.Join(fmt.Errorf("duplicate worker standard handle: %w", err), closeWorkerHandles(handles))
		}
		handles = append(handles, duplicate)
		runtime.KeepAlive(file)
	}
	return handles, nil
}

func closeWorkerHandles(handles []windows.Handle) error {
	errorsToJoin := make([]error, 0, len(handles))
	for _, handle := range handles {
		if handle == 0 || handle == windows.InvalidHandle {
			continue
		}
		if err := windows.CloseHandle(handle); err != nil {
			errorsToJoin = append(errorsToJoin, err)
		}
	}
	return errors.Join(errorsToJoin...)
}

func abortWindowsWorker(job, process, thread windows.Handle) error {
	var terminateErr, threadErr, jobErr, fallbackErr, waitErr, processErr error
	if job != 0 {
		terminateErr = windows.TerminateJobObject(job, workerForcedExitCode)
	}
	if thread != 0 {
		threadErr = windows.CloseHandle(thread)
	}
	if job != 0 {
		// KILL_ON_JOB_CLOSE is the fail-closed fallback if explicit termination
		// fails. The process handle remains open until the termination is observed.
		jobErr = windows.CloseHandle(job)
	}
	if terminateErr != nil && jobErr != nil && process != 0 {
		fallbackErr = windows.TerminateProcess(process, workerForcedExitCode)
	}
	if process != 0 {
		result, err := windows.WaitForSingleObject(process, 10_000)
		if err != nil {
			waitErr = err
		} else if result != windows.WAIT_OBJECT_0 {
			waitErr = fmt.Errorf("worker cleanup wait returned status %#x", result)
		}
		processErr = windows.CloseHandle(process)
	}
	return errors.Join(terminateErr, threadErr, jobErr, fallbackErr, waitErr, processErr)
}

func workerJobOOM(job windows.Handle, exitCode uint32) (bool, error) {
	violationFlags, violationErr := queryWorkerJobViolationFlags(job)
	limits, limitsErr := queryWorkerJobLimits(job)

	oom := violationFlags&(windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY|windows.JOB_OBJECT_LIMIT_JOB_MEMORY) != 0 ||
		workerExitCodeIsOOM(exitCode)
	if limitsErr == nil && exitCode != 0 {
		oom = oom ||
			limits.PeakProcessMemoryUsed >= limits.ProcessMemoryLimit ||
			limits.PeakJobMemoryUsed >= limits.JobMemoryLimit
	}
	if violationErr != nil && limitsErr != nil {
		return oom, fmt.Errorf("classify worker memory failure: %w", errors.Join(violationErr, limitsErr))
	}
	return oom, nil
}

func workerExitCodeIsOOM(exitCode uint32) bool {
	return exitCode == statusNoMemory || exitCode == statusCommitmentLimit
}

func queryWorkerJobViolationFlags(job windows.Handle) (uint32, error) {
	var current jobObjectLimitViolationInformation2
	if err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectLimitViolationInformation2,
		uintptr(unsafe.Pointer(&current)),
		uint32(unsafe.Sizeof(current)),
		nil,
	); err == nil {
		return current.ViolationLimitFlags, nil
	}

	var legacy jobObjectLimitViolationInformation
	if err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectLimitViolationInformation,
		uintptr(unsafe.Pointer(&legacy)),
		uint32(unsafe.Sizeof(legacy)),
		nil,
	); err != nil {
		return 0, err
	}
	return legacy.ViolationLimitFlags, nil
}

func queryWorkerJobLimits(job windows.Handle) (windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION, error) {
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
		nil,
	); err != nil {
		return windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}, err
	}
	return limits, nil
}
