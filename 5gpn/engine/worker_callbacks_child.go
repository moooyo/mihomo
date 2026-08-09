package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

const maxWorkerStorageCallsPerAction = 128

var errWorkerRPCSealed = errors.New("extension worker callback channel is sealed")

type workerRPCClient struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	reader *workerFrameReader
	writer *workerFrameWriter

	nextID  atomic.Uint64
	mu      sync.Mutex
	pending map[uint64]workerPendingCall
	closed  bool
	sealed  bool
	done    chan struct{}
	once    sync.Once
}

func (client *workerRPCClient) sealAndWait(ctx context.Context) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	client.mu.Lock()
	client.sealed = true
	client.mu.Unlock()
	for {
		client.mu.Lock()
		pending := len(client.pending)
		closed := client.closed
		client.mu.Unlock()
		if pending == 0 {
			if closed {
				return context.Cause(client.ctx)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-client.ctx.Done():
			return context.Cause(client.ctx)
		case <-ticker.C:
		}
	}
}

type workerPendingCall struct {
	want workerFrameKind
	ch   chan workerCallResult
}

type workerCallResult struct {
	frame workerFrame
	err   error
}

func newWorkerRPCClient(parent context.Context, reader *workerFrameReader, writer *workerFrameWriter) *workerRPCClient {
	ctx, cancel := context.WithCancelCause(parent)
	client := &workerRPCClient{
		ctx: ctx, cancel: cancel, reader: reader, writer: writer,
		pending: make(map[uint64]workerPendingCall), done: make(chan struct{}),
	}
	go client.readLoop()
	return client
}

func (client *workerRPCClient) Close() {
	if client == nil {
		return
	}
	client.fail(context.Canceled)
}

func (client *workerRPCClient) readLoop() {
	for {
		frame, err := client.reader.ReadFrame()
		if err != nil {
			client.fail(err)
			return
		}
		client.mu.Lock()
		pending, exists := client.pending[frame.ID]
		if exists {
			delete(client.pending, frame.ID)
		}
		client.mu.Unlock()
		if !exists || frame.Kind != pending.want {
			client.fail(fmt.Errorf("%w: unexpected callback response %s/%d", errWorkerProtocol, frame.Kind, frame.ID))
			return
		}
		pending.ch <- workerCallResult{frame: frame}
	}
}

func (client *workerRPCClient) fail(err error) {
	if client == nil {
		return
	}
	client.once.Do(func() {
		if err == nil {
			err = ioEOFWorkerProtocol()
		}
		client.cancel(err)
		client.mu.Lock()
		client.closed = true
		pending := client.pending
		client.pending = make(map[uint64]workerPendingCall)
		client.mu.Unlock()
		for _, call := range pending {
			call.ch <- workerCallResult{err: err}
		}
		close(client.done)
	})
}

func ioEOFWorkerProtocol() error {
	return fmt.Errorf("%w: callback channel closed", errWorkerProtocol)
}

func (client *workerRPCClient) call(ctx context.Context, request workerFrame, want workerFrameKind) (workerFrame, error) {
	if client == nil {
		return workerFrame{}, ErrHardIsolationUnavailable
	}
	id := client.nextID.Add(2)
	if id == 0 {
		return workerFrame{}, fmt.Errorf("%w: callback id exhausted", errWorkerProtocol)
	}
	request.ID = id
	response := make(chan workerCallResult, 1)
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return workerFrame{}, context.Cause(client.ctx)
	}
	if client.sealed {
		client.mu.Unlock()
		return workerFrame{}, errWorkerRPCSealed
	}
	client.pending[id] = workerPendingCall{want: want, ch: response}
	client.mu.Unlock()
	if err := client.writer.WriteFrame(request); err != nil {
		client.mu.Lock()
		delete(client.pending, id)
		client.mu.Unlock()
		client.fail(err)
		return workerFrame{}, err
	}
	select {
	case result := <-response:
		return result.frame, result.err
	case <-ctx.Done():
		client.fail(ctx.Err())
		return workerFrame{}, ctx.Err()
	case <-client.ctx.Done():
		return workerFrame{}, context.Cause(client.ctx)
	}
}

func (client *workerRPCClient) Network(request moduleNetworkRequest, wait bool) (moduleNetworkResponse, error) {
	metadata, err := marshalWorkerMetadata(workerNetworkRequestMetadata{
		URL: request.url.String(), Method: request.method,
		Headers: map[string][]string(request.headers), HasBody: request.hasBody, Wait: wait,
	})
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	frame, err := client.call(client.ctx, workerFrame{
		Kind: workerFrameKindNetworkRequest, Metadata: metadata, Blob1: request.body,
	}, workerFrameKindNetworkResponse)
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	if len(frame.Blob2) != 0 {
		return moduleNetworkResponse{}, fmt.Errorf("%w: network response has a second blob", errWorkerProtocol)
	}
	var response workerNetworkResponseMetadata
	if err := unmarshalWorkerMetadata(frame.Metadata, &response); err != nil {
		return moduleNetworkResponse{}, err
	}
	if response.Error != "" {
		if len(frame.Blob1) != 0 {
			return moduleNetworkResponse{}, fmt.Errorf("%w: failed network response has a body", errWorkerProtocol)
		}
		return moduleNetworkResponse{}, errors.New(response.Error)
	}
	return moduleNetworkResponse{
		url: response.URL, status: response.StatusCode,
		headers: response.Headers, trailers: response.Trailers, body: frame.Blob1,
	}, nil
}

func (client *workerRPCClient) StorageObject(vm *goja.Runtime) *goja.Object {
	storage := vm.NewObject()
	calls := 0
	call := func(operation, key, value string) workerCallResult {
		calls++
		if calls > maxWorkerStorageCallsPerAction {
			panic(vm.NewGoError(errors.New("storage call limit exceeded")))
		}
		metadata, err := marshalWorkerMetadata(workerStorageRequestMetadata{Operation: operation, Key: key})
		if err != nil {
			panic(vm.NewGoError(err))
		}
		frame, err := client.call(client.ctx, workerFrame{
			Kind: workerFrameKindStorageRequest, Metadata: metadata, Blob1: []byte(value),
		}, workerFrameKindStorageResponse)
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return workerCallResult{frame: frame}
	}
	_ = storage.Set("get", func(invocation goja.FunctionCall) goja.Value {
		result := call("get", invocation.Argument(0).String(), "")
		response := decodeWorkerStorageResponse(vm, result.frame)
		if !response.Exists {
			return goja.Null()
		}
		return vm.ToValue(string(result.frame.Blob1))
	})
	_ = storage.Set("set", func(invocation goja.FunctionCall) goja.Value {
		result := call("set", invocation.Argument(0).String(), invocation.Argument(1).String())
		return vm.ToValue(decodeWorkerStorageResponse(vm, result.frame).OK)
	})
	_ = storage.Set("delete", func(invocation goja.FunctionCall) goja.Value {
		result := call("delete", invocation.Argument(0).String(), "")
		return vm.ToValue(decodeWorkerStorageResponse(vm, result.frame).OK)
	})
	_ = storage.Set("clear", func(goja.FunctionCall) goja.Value {
		result := call("clear", "", "")
		return vm.ToValue(decodeWorkerStorageResponse(vm, result.frame).OK)
	})
	return storage
}

func decodeWorkerStorageResponse(vm *goja.Runtime, frame workerFrame) workerStorageResponseMetadata {
	if len(frame.Blob2) != 0 || len(frame.Blob1) > maxPersistentValueBytes {
		panic(vm.NewGoError(fmt.Errorf("%w: invalid storage response body", errWorkerProtocol)))
	}
	var response workerStorageResponseMetadata
	if err := unmarshalWorkerMetadata(frame.Metadata, &response); err != nil {
		panic(vm.NewGoError(err))
	}
	if response.Error != "" {
		panic(vm.NewGoError(errors.New(response.Error)))
	}
	return response
}

type workerRPCLogPublisher struct {
	client  *workerRPCClient
	dropped atomic.Uint64
}

func (publisher *workerRPCLogPublisher) Enabled() bool {
	return publisher != nil && publisher.client != nil
}
func (publisher *workerRPCLogPublisher) Dropped() uint64 { return publisher.dropped.Load() }

func (publisher *workerRPCLogPublisher) Publish(event EngineLog) {
	if !publisher.Enabled() {
		return
	}
	metadata, err := marshalWorkerMetadata(workerLogMetadata{
		Level: event.Level, Message: event.Message,
	})
	if err != nil {
		publisher.dropped.Add(1)
		publisher.client.fail(err)
		return
	}
	frame, err := publisher.client.call(publisher.client.ctx, workerFrame{
		Kind: workerFrameKindLog, Metadata: metadata,
	}, workerFrameKindLogAck)
	if err != nil {
		publisher.dropped.Add(1)
		return
	}
	var ack workerAckMetadata
	if len(frame.Blob1)+len(frame.Blob2) != 0 || unmarshalWorkerMetadata(frame.Metadata, &ack) != nil || !ack.OK {
		publisher.dropped.Add(1)
		publisher.client.fail(fmt.Errorf("%w: invalid log acknowledgement", errWorkerProtocol))
	}
}
