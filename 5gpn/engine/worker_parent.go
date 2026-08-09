package engine

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	workerBootstrapTimeout = 10 * time.Second
	workerStderrLimit      = 8 << 10
)

type workerController struct {
	isolation  *workerIsolation
	executable string
	closed     atomic.Bool
	slots      chan struct{}
}

func newWorkerController() (*workerController, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("%w: locate current executable: %v", ErrHardIsolationUnavailable, err)
	}
	isolation, err := newWorkerIsolation(
		workerPerProcessMemoryBytes,
		workerAggregateMemoryBytes,
		workerMaximumProcesses,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHardIsolationUnavailable, err)
	}
	controller := &workerController{
		isolation: isolation, executable: executable,
		slots: make(chan struct{}, int(workerMaximumProcesses)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), workerBootstrapTimeout)
	defer cancel()
	if err := controller.probe(ctx); err != nil {
		_ = controller.Close()
		return nil, fmt.Errorf("%w: startup probe: %v", ErrHardIsolationUnavailable, err)
	}
	return controller, nil
}

func (controller *workerController) Close() error {
	if controller == nil || controller.isolation == nil || controller.closed.Swap(true) {
		return nil
	}
	return controller.isolation.Close()
}

func (controller *workerController) probe(ctx context.Context) error {
	frame, err := controller.run(ctx, workerFrame{Kind: workerFrameKindProbe, ID: 1})
	if err != nil {
		return err
	}
	if frame.Kind != workerFrameKindResult || frame.ID != 1 || len(frame.Metadata)+len(frame.Blob1)+len(frame.Blob2) != 0 {
		return fmt.Errorf("%w: invalid probe result", errWorkerProtocol)
	}
	return nil
}

func (controller *workerController) Validate(ctx context.Context, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxConfigBytes {
		return errors.New("extension configuration is outside validation bounds")
	}
	frame, err := controller.run(ctx, workerFrame{Kind: workerFrameKindValidate, ID: 1, Blob1: raw})
	if err != nil {
		return err
	}
	switch frame.Kind {
	case workerFrameKindResult:
		if len(frame.Metadata)+len(frame.Blob1)+len(frame.Blob2) != 0 {
			return fmt.Errorf("%w: invalid validation result", errWorkerProtocol)
		}
		return nil
	case workerFrameKindError:
		guestErr := workerError(frame)
		if errors.Is(guestErr, errWorkerProtocol) || errors.Is(guestErr, errWorkerMetadataInvalid) {
			return guestErr
		}
		return fmt.Errorf("%w: %v", ErrInvalidRequest, guestErr)
	default:
		return fmt.Errorf("%w: unexpected validation terminal %s", errWorkerProtocol, frame.Kind)
	}
}

func (controller *workerController) Execute(
	ctx context.Context,
	runtimeState *scriptRuntime,
	_ Config,
	roots *x509.CertPool,
	module Module,
	rule ScriptRule,
	request scriptMessage,
	response *scriptMessage,
) (scriptResult, error) {
	if controller == nil || controller.closed.Load() {
		return scriptResult{}, ErrHardIsolationUnavailable
	}
	settings, err := scriptSettingValues(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	remaining := time.Duration(rule.TimeoutMS) * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}
	if remaining <= 0 {
		return scriptResult{}, context.DeadlineExceeded
	}
	remainingMillis := remaining.Milliseconds()
	if remainingMillis <= 0 {
		return scriptResult{}, context.DeadlineExceeded
	}
	metadata := workerActionMetadata{
		ModuleID: module.ID, Network: module.Network, Persistent: module.PersistentStorage,
		Rule: workerRuleFrom(rule), Settings: settings, Request: workerMessageFrom(request),
		TimeoutMillis: remainingMillis,
	}
	var requestBody []byte
	if response == nil && rule.BodyMode != "none" {
		requestBody = request.Body
	}
	var responseBody []byte
	if response != nil {
		projection := workerMessageFrom(*response)
		metadata.Response = &projection
		if rule.BodyMode != "none" {
			responseBody = response.Body
		}
	}
	encoded, err := marshalWorkerMetadata(metadata)
	if err != nil {
		return scriptResult{}, err
	}
	session := &workerParentSession{
		runtime: runtimeState, module: module, rule: rule,
		request: request,
		storage: workerStorageSession{runtime: runtimeState, moduleID: module.ID},
	}
	if module.Network {
		session.network = newModuleNetworkRequester(ctx, roots, runtimeState.networkSlots, module.ID)
		defer session.network.Close()
	}
	frame, err := controller.runWithSession(ctx, workerFrame{
		Kind: workerFrameKindExecute, ID: 1, Metadata: encoded,
		Blob1: requestBody, Blob2: responseBody,
	}, session)
	if err != nil {
		return scriptResult{}, err
	}
	if frame.ID != 1 {
		return scriptResult{}, fmt.Errorf("%w: terminal correlation id changed", errWorkerProtocol)
	}
	switch frame.Kind {
	case workerFrameKindError:
		return scriptResult{}, workerError(frame)
	case workerFrameKindResult:
		var resultMetadata workerResultMetadata
		if err := unmarshalWorkerMetadata(frame.Metadata, &resultMetadata); err != nil {
			return scriptResult{}, err
		}
		result := resultMetadata.scriptResult(frame.Blob1)
		if len(frame.Blob2) != 0 {
			return scriptResult{}, fmt.Errorf("%w: action result has an unexpected second blob", errWorkerProtocol)
		}
		if err := validateWorkerResult(rule, &result); err != nil {
			return scriptResult{}, err
		}
		return result, nil
	default:
		return scriptResult{}, fmt.Errorf("%w: unexpected action terminal %s", errWorkerProtocol, frame.Kind)
	}
}

func validateWorkerResult(rule ScriptRule, result *scriptResult) error {
	if result == nil {
		return fmt.Errorf("%w: worker returned a nil result", errWorkerProtocol)
	}
	if len(result.URL) > maxModuleRequestRewriteURLBytes || int64(len(result.Body)) > maxModuleHTTPBody || int64(len(result.Body)) > rule.MaxBodyBytes {
		return fmt.Errorf("%w: worker result exceeds action bounds", errWorkerProtocol)
	}
	if !result.ChangedURL && result.URL != "" || !result.ChangedBody && len(result.Body) != 0 ||
		!result.ChangedHeaders && len(result.Headers) != 0 ||
		!result.ChangedTrailers && len(result.Trailers) != 0 ||
		!result.ChangedStatus && result.StatusCode != 0 {
		return fmt.Errorf("%w: worker returned data without its change flag", errWorkerProtocol)
	}
	if rule.Phase == "response" && (result.ChangedURL || result.Synthetic) {
		return fmt.Errorf("%w: response action returned a request-only result", errWorkerProtocol)
	}
	if rule.Phase == "request" && !result.Synthetic && (result.ChangedTrailers || result.ChangedStatus) {
		return fmt.Errorf("%w: request patch returned response-only fields", errWorkerProtocol)
	}
	if result.Synthetic && result.ChangedURL {
		return fmt.Errorf("%w: synthetic response also changed the request URL", errWorkerProtocol)
	}
	if result.ChangedHeaders {
		headers, err := exportedHeaders(map[string][]string(result.Headers))
		if err != nil {
			return fmt.Errorf("%w: invalid worker headers: %v", errWorkerProtocol, err)
		}
		result.Headers = headers
		if err := validateNativePatchHeaders(result.Headers, result.Synthetic || rule.Phase == "response"); err != nil {
			return fmt.Errorf("%w: invalid worker headers: %v", errWorkerProtocol, err)
		}
	}
	if result.ChangedTrailers {
		if rule.Phase != "response" && !result.Synthetic {
			return fmt.Errorf("%w: request result changed trailers", errWorkerProtocol)
		}
		trailers, err := exportedTrailers(map[string][]string(result.Trailers))
		if err != nil {
			return fmt.Errorf("%w: invalid worker trailers: %v", errWorkerProtocol, err)
		}
		result.Trailers = trailers
	}
	if result.ChangedStatus && (result.StatusCode < 100 || result.StatusCode > 599) {
		return fmt.Errorf("%w: invalid worker status", errWorkerProtocol)
	}
	return nil
}

func (controller *workerController) run(ctx context.Context, task workerFrame) (workerFrame, error) {
	return controller.runWithSession(ctx, task, nil)
}

func (controller *workerController) runWithSession(ctx context.Context, task workerFrame, session *workerParentSession) (_ workerFrame, retErr error) {
	if controller == nil || controller.isolation == nil || controller.closed.Load() {
		return workerFrame{}, ErrHardIsolationUnavailable
	}
	if err := controller.acquire(); err != nil {
		return workerFrame{}, err
	}
	defer controller.release()
	childInput, parentInput, err := os.Pipe()
	if err != nil {
		return workerFrame{}, err
	}
	parentOutput, childOutput, err := os.Pipe()
	if err != nil {
		childInput.Close()
		parentInput.Close()
		return workerFrame{}, err
	}
	parentError, childError, err := os.Pipe()
	if err != nil {
		childInput.Close()
		parentInput.Close()
		parentOutput.Close()
		childOutput.Close()
		return workerFrame{}, err
	}
	defer parentInput.Close()
	defer parentOutput.Close()
	stderr, joinStderr := startWorkerStderrDrain(parentError)
	defer func() {
		joinStderr()
		if output := stderr.String(); retErr != nil && output != "" {
			retErr = fmt.Errorf("%w; stderr=%q", retErr, output)
		}
	}()

	process, err := controller.isolation.Start(ctx, workerProcessSpec{
		Executable: controller.executable,
		Args:       []string{ExtensionWorkerCommand},
		Env:        workerEnvironment(),
		Stdin:      childInput, Stdout: childOutput, Stderr: childError,
	})
	childInput.Close()
	childOutput.Close()
	childError.Close()
	if err != nil {
		return workerFrame{}, fmt.Errorf("%w: start worker: %v", ErrHardIsolationUnavailable, err)
	}
	var callbackWG sync.WaitGroup
	defer func() {
		if retErr != nil {
			_ = process.Kill()
			_ = parentInput.Close()
		}
		callbackWG.Wait()
		retErr = errors.Join(retErr, process.Close())
	}()
	stopKill := context.AfterFunc(ctx, func() { _ = process.Kill() })
	defer stopKill()

	reader := newWorkerFrameReader(parentOutput)
	writer := newWorkerFrameWriter(parentInput)
	if err := writer.WriteFrame(workerFrame{Kind: workerFrameKindGate}); err != nil {
		return workerFrame{}, err
	}
	ready, err := reader.ReadFrame()
	if err != nil {
		return workerFrame{}, workerProtocolProcessFailure(process, err)
	}
	var readyMetadata workerReadyMetadata
	if ready.Kind != workerFrameKindReady || ready.ID != 0 || len(ready.Blob1)+len(ready.Blob2) != 0 ||
		unmarshalWorkerMetadata(ready.Metadata, &readyMetadata) != nil || readyMetadata.Protocol != workerProtocolVersion {
		return workerFrame{}, fmt.Errorf("%w: invalid worker ready frame", errWorkerProtocol)
	}
	if err := writer.WriteFrame(task); err != nil {
		return workerFrame{}, err
	}

	var callbackErr atomic.Pointer[error]
	setCallbackErr := func(err error) {
		if err == nil {
			return
		}
		copy := err
		callbackErr.CompareAndSwap(nil, &copy)
		_ = process.Kill()
	}
	var terminal workerFrame
	for {
		frame, readErr := reader.ReadFrame()
		if readErr != nil {
			return workerFrame{}, workerProtocolProcessFailure(process, readErr)
		}
		switch frame.Kind {
		case workerFrameKindNetworkRequest:
			if session == nil {
				return workerFrame{}, fmt.Errorf("%w: callback during non-execution task", errWorkerProtocol)
			}
			if err := session.reserveNetworkCallback(); err != nil {
				return workerFrame{}, err
			}
			callbackWG.Add(1)
			go func(frame workerFrame) {
				defer callbackWG.Done()
				setCallbackErr(session.handleNetwork(ctx, writer, frame))
			}(frame)
		case workerFrameKindStorageRequest:
			if session == nil {
				return workerFrame{}, fmt.Errorf("%w: callback during non-execution task", errWorkerProtocol)
			}
			if err := session.handleStorage(writer, frame); err != nil {
				return workerFrame{}, err
			}
		case workerFrameKindLog:
			if session == nil {
				return workerFrame{}, fmt.Errorf("%w: callback during non-execution task", errWorkerProtocol)
			}
			if err := session.handleLog(writer, frame); err != nil {
				return workerFrame{}, err
			}
		case workerFrameKindResult, workerFrameKindError:
			if frame.ID != task.ID {
				return workerFrame{}, fmt.Errorf("%w: terminal id does not match task", errWorkerProtocol)
			}
			terminal = frame
			goto terminalReceived
		default:
			return workerFrame{}, fmt.Errorf("%w: unexpected child frame %s", errWorkerProtocol, frame.Kind)
		}
	}

terminalReceived:
	callbackWG.Wait()
	if callback := callbackErr.Load(); callback != nil {
		return workerFrame{}, *callback
	}
	if err := parentInput.Close(); err != nil {
		return workerFrame{}, err
	}
	if _, err := reader.ReadFrame(); !errors.Is(err, io.EOF) {
		if err == nil {
			return workerFrame{}, fmt.Errorf("%w: data followed terminal frame", errWorkerProtocol)
		}
		return workerFrame{}, err
	}
	exit, waitErr := process.Wait()
	joinStderr()
	if waitErr != nil || exit.Code != 0 || exit.OOM {
		classification := "crashed"
		if exit.OOM {
			classification = "exceeded its memory limit"
		}
		return workerFrame{}, errors.Join(
			fmt.Errorf("extension worker %s (exit=%d); stderr=%q", classification, exit.Code, stderr.String()),
			waitErr,
		)
	}
	return terminal, nil
}

func startWorkerStderrDrain(reader *os.File) (*boundedWorkerBuffer, func()) {
	buffer := &boundedWorkerBuffer{limit: workerStderrLimit}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(buffer, reader)
		close(done)
	}()
	var once sync.Once
	return buffer, func() {
		once.Do(func() {
			<-done
			_ = reader.Close()
		})
	}
}

func (controller *workerController) acquire() error {
	if controller == nil || controller.closed.Load() {
		return ErrHardIsolationUnavailable
	}
	select {
	case controller.slots <- struct{}{}:
		return nil
	default:
		return ErrWorkerCapacity
	}
}

func (controller *workerController) release() {
	if controller == nil {
		return
	}
	select {
	case <-controller.slots:
	default:
	}
}

func workerProtocolProcessFailure(process *workerProcess, protocolErr error) error {
	if process == nil {
		return protocolErr
	}
	killErr := process.Kill()
	exit, waitErr := process.Wait()
	if exit.OOM {
		return errors.Join(fmt.Errorf("extension worker exceeded its memory limit: %w", protocolErr), killErr)
	}
	if waitErr != nil || exit.Code != 0 {
		return errors.Join(
			fmt.Errorf("extension worker exited before a terminal result (exit=%d): %v: %w", exit.Code, waitErr, protocolErr),
			killErr,
		)
	}
	return errors.Join(protocolErr, killErr)
}

func workerEnvironment() []string {
	environment := []string{
		"GOMEMLIMIT=384MiB",
		"GOGC=50",
		"GOMAXPROCS=2",
	}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"SystemRoot", "WINDIR"} {
			if value, ok := os.LookupEnv(name); ok {
				environment = append(environment, name+"="+value)
			}
		}
	}
	return environment
}

type boundedWorkerBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	limit  int
}

func (buffer *boundedWorkerBuffer) Write(body []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > len(body) {
		remaining = len(body)
	}
	if remaining > 0 {
		_, _ = buffer.buffer.Write(body[:remaining])
	}
	return len(body), nil
}

func (buffer *boundedWorkerBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}
