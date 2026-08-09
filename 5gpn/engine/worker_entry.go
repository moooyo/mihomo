package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExtensionWorkerCommand is deliberately not part of the public CLI. It is
// accepted only as argv[1] by the same binary that spawned it and speaks a
// private, versioned protocol over inherited anonymous pipes.
const ExtensionWorkerCommand = "5gpn-extension-worker-v1"

func init() {
	// A `go test` binary has the generated testing main rather than mihomo's
	// main.go. Dispatch the same hidden command here only for that binary shape;
	// installed binaries always take the facade/main path below.
	if isWorkerTestBinaryEarly() && len(os.Args) > 1 && os.Args[1] == ExtensionWorkerCommand {
		os.Exit(ExtensionWorkerMain(os.Args[2:]))
	}
}

func isWorkerTestBinaryEarly() bool {
	return isWorkerTestBinaryPath(os.Args[0])
}

func isWorkerTestBinaryPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(base, ".test") || strings.HasSuffix(base, ".test.exe")
}

// ExtensionWorkerMain runs one short-lived extension operation. Go package
// initializers have already run, but dispatch occurs before ordinary main,
// configuration, and listener setup. The worker receives a minimal environment
// and reads no task bytes until it has dropped capabilities and passed the
// parent-controlled gate.
func ExtensionWorkerMain(args []string) int {
	initializeGuestSafetyLimits()
	return runExtensionWorkerChild(os.Stdin, os.Stdout, os.Stderr, args)
}

func runExtensionWorkerChild(stdin io.Reader, stdout io.Writer, stderr io.Writer, args []string) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "extension worker: arguments are not accepted")
		return 64
	}
	if err := dropWorkerPrivileges(); err != nil {
		_, _ = fmt.Fprintf(stderr, "extension worker: drop privileges: %v\n", err)
		return 70
	}
	reader := newWorkerFrameReader(stdin)
	writer := newWorkerFrameWriter(stdout)
	gate, err := reader.ReadFrame()
	if err != nil || gate.Kind != workerFrameKindGate || gate.ID != 0 ||
		len(gate.Metadata)+len(gate.Blob1)+len(gate.Blob2) != 0 {
		_, _ = fmt.Fprintln(stderr, "extension worker: invalid bootstrap gate")
		return 70
	}
	ready, err := marshalWorkerMetadata(workerReadyMetadata{Protocol: workerProtocolVersion})
	if err != nil || writer.WriteFrame(workerFrame{Kind: workerFrameKindReady, Metadata: ready}) != nil {
		_, _ = fmt.Fprintln(stderr, "extension worker: ready handshake failed")
		return 70
	}
	task, err := reader.ReadFrame()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "extension worker: task frame failed")
		return 70
	}
	switch task.Kind {
	case workerFrameKindProbe:
		if len(task.Metadata)+len(task.Blob1)+len(task.Blob2) != 0 {
			return writeWorkerTaskError(writer, task.ID, errors.New("probe task is not empty"), stderr)
		}
		if err := writer.WriteFrame(workerFrame{Kind: workerFrameKindResult, ID: task.ID}); err != nil {
			return 70
		}
		return 0
	case workerFrameKindValidate:
		return runWorkerValidation(writer, task, stderr)
	case workerFrameKindExecute:
		return runWorkerExecution(reader, writer, task, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "extension worker: unexpected task %s\n", task.Kind)
		return 70
	}
}

func runWorkerValidation(writer *workerFrameWriter, task workerFrame, stderr io.Writer) int {
	if len(task.Metadata)+len(task.Blob2) != 0 || len(task.Blob1) == 0 {
		return writeWorkerTaskError(writer, task.ID, errors.New("validation task shape is invalid"), stderr)
	}
	cfg, err := decodeConfig(task.Blob1)
	if err == nil {
		err = validateGuestPrograms(cfg)
	}
	if err != nil {
		return writeWorkerTaskError(writer, task.ID, err, stderr)
	}
	if err := writer.WriteFrame(workerFrame{Kind: workerFrameKindResult, ID: task.ID}); err != nil {
		return 70
	}
	return 0
}

func runWorkerExecution(reader *workerFrameReader, writer *workerFrameWriter, task workerFrame, stderr io.Writer) int {
	var metadata workerActionMetadata
	if err := unmarshalWorkerMetadata(task.Metadata, &metadata); err != nil {
		return writeWorkerTaskError(writer, task.ID, err, stderr)
	}
	if err := validateWorkerActionTask(metadata, task.Blob1, task.Blob2); err != nil {
		return writeWorkerTaskError(writer, task.ID, err, stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(metadata.TimeoutMillis)*time.Millisecond)
	defer cancel()
	client := newWorkerRPCClient(ctx, reader, writer)
	logs := &workerRPCLogPublisher{client: client}
	runtimeState := &scriptRuntime{workerClient: client, logs: logs}
	module := Module{
		ID: metadata.ModuleID, Network: metadata.Network,
		PersistentStorage: metadata.Persistent,
	}
	rule := metadata.Rule.scriptRule(metadata.Settings)
	request := metadata.Request.scriptMessage(task.Blob1)
	var response *scriptMessage
	if metadata.Response != nil {
		value := metadata.Response.scriptMessage(task.Blob2)
		response = &value
	}
	result, err := runtimeState.executeGuest(ctx, module, rule, request, response)
	if idleErr := client.sealAndWait(ctx); idleErr != nil {
		err = errors.Join(err, idleErr)
	}
	if err == nil {
		if cause := context.Cause(client.ctx); cause != nil {
			err = cause
		}
	}
	if err != nil {
		return writeWorkerTaskError(writer, task.ID, err, stderr)
	}
	resultMetadata, err := marshalWorkerMetadata(workerResultFrom(result))
	if err != nil {
		return writeWorkerTaskError(writer, task.ID, err, stderr)
	}
	if err := writer.WriteFrame(workerFrame{
		Kind: workerFrameKindResult, ID: task.ID, Metadata: resultMetadata, Blob1: result.Body,
	}); err != nil {
		_, _ = fmt.Fprintf(stderr, "extension worker: write result: %v\n", err)
		return 70
	}
	return 0
}

func validateWorkerActionTask(metadata workerActionMetadata, requestBody, responseBody []byte) error {
	if !validModuleID(metadata.ModuleID) {
		return errors.New("action module id is invalid")
	}
	rule := metadata.Rule
	if !validSettingKey(rule.ID) || (rule.Phase != "request" && rule.Phase != "response") {
		return errors.New("action identity is invalid")
	}
	if rule.BodyMode != "none" && rule.BodyMode != "text" && rule.BodyMode != "binary" {
		return errors.New("action body mode is invalid")
	}
	if rule.TimeoutMS < 50 || rule.TimeoutMS > 30000 || metadata.TimeoutMillis <= 0 || metadata.TimeoutMillis > int64(rule.TimeoutMS) ||
		rule.MaxBodyBytes < 1024 || rule.MaxBodyBytes > maxModuleHTTPBody {
		return errors.New("action limits are invalid")
	}
	if rule.Entry != "" && rule.Entry != scriptEntryProxyCompat {
		return errors.New("action entry is invalid")
	}
	codeKinds := 0
	if rule.ScriptBody != "" {
		codeKinds++
		if len(rule.ScriptBody) > maxScriptBytes || rule.ScriptDigest != digestText(rule.ScriptBody) {
			return errors.New("action script snapshot is invalid")
		}
	}
	if rule.JQProgram != "" {
		codeKinds++
		if len(rule.JQProgram) > maxJQProgramBytes || rule.BodyMode != "text" || rule.Entry != "" {
			return errors.New("action jq program is invalid")
		}
	}
	if codeKinds != 1 {
		return errors.New("execution task must contain exactly one guest program")
	}
	if int64(len(requestBody)) > rule.MaxBodyBytes || int64(len(responseBody)) > rule.MaxBodyBytes {
		return errors.New("action input body exceeds its limit")
	}
	if rule.BodyMode == "none" && (len(requestBody) != 0 || len(responseBody) != 0) {
		return errors.New("bodyless action received body bytes")
	}
	if rule.Phase == "response" && metadata.Response == nil {
		return errors.New("response action has no response")
	}
	if rule.Phase == "request" && metadata.Response != nil {
		return errors.New("request action received response metadata")
	}
	if metadata.Response != nil && len(requestBody) != 0 {
		return errors.New("response action received request body bytes")
	}
	if metadata.Response == nil && len(responseBody) != 0 {
		return errors.New("response body has no response metadata")
	}
	return nil
}

func writeWorkerTaskError(writer *workerFrameWriter, id uint64, taskErr error, stderr io.Writer) int {
	message := "extension operation failed"
	if taskErr != nil {
		message = truncateEngineLogField(taskErr.Error(), maxEngineLogMessageBytes)
	}
	metadata, err := marshalWorkerMetadata(workerErrorMetadata{Code: "operation_failed", Message: message})
	if err != nil || writer.WriteFrame(workerFrame{Kind: workerFrameKindError, ID: id, Metadata: metadata}) != nil {
		_, _ = fmt.Fprintln(stderr, "extension worker: write terminal error failed")
		return 70
	}
	return 0
}
