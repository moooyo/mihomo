package engine

import (
	"context"
	"fmt"
	"sync"
	"unicode/utf8"
)

const maxWorkerLogCallbacksPerAction = maxConsoleLogsPerAction + 8

type workerParentSession struct {
	runtime *scriptRuntime
	module  Module
	rule    ScriptRule
	request scriptMessage

	networkMu    sync.Mutex
	networkCalls int
	network      *moduleNetworkRequester
	storage      workerStorageSession
	storageCalls int
	logCount     int
}

func (session *workerParentSession) handleNetwork(ctx context.Context, writer *workerFrameWriter, frame workerFrame) error {
	if !session.module.Network || session.network == nil {
		return fmt.Errorf("%w: worker requested network without a grant", errWorkerProtocol)
	}
	if len(frame.Blob2) != 0 {
		return fmt.Errorf("%w: network request has a second blob", errWorkerProtocol)
	}
	var metadata workerNetworkRequestMetadata
	if err := unmarshalWorkerMetadata(frame.Metadata, &metadata); err != nil {
		return err
	}
	options := map[string]any{
		"url":     metadata.URL,
		"method":  metadata.Method,
		"headers": metadata.Headers,
	}
	if metadata.HasBody {
		options["body"] = frame.Blob1
	} else if len(frame.Blob1) != 0 {
		return fmt.Errorf("%w: body bytes without has_body", errWorkerProtocol)
	}
	request, err := newModuleNetworkRequest(options)
	if err != nil {
		return writeWorkerNetworkResponse(writer, frame.ID, moduleNetworkResponse{}, err)
	}
	var response moduleNetworkResponse
	if metadata.Wait {
		response, err = session.network.requestWaiting(request)
	} else {
		response, err = session.network.request(request)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return writeWorkerNetworkResponse(writer, frame.ID, response, err)
}

func (session *workerParentSession) reserveNetworkCallback() error {
	session.networkMu.Lock()
	defer session.networkMu.Unlock()
	if !session.module.Network || session.network == nil {
		return fmt.Errorf("%w: worker requested network without a grant", errWorkerProtocol)
	}
	if session.networkCalls >= maxModuleNetworkCallsPerAction {
		return fmt.Errorf("%w: worker exceeded the network call limit", errWorkerProtocol)
	}
	session.networkCalls++
	return nil
}

func writeWorkerNetworkResponse(writer *workerFrameWriter, id uint64, response moduleNetworkResponse, requestErr error) error {
	metadata := workerNetworkResponseMetadata{}
	var body []byte
	if requestErr != nil {
		metadata.Error = truncateEngineLogField(requestErr.Error(), maxEngineLogMessageBytes)
	} else {
		metadata.URL = response.url
		metadata.StatusCode = response.status
		metadata.Headers = response.headers
		metadata.Trailers = response.trailers
		body = response.body
	}
	encoded, err := marshalWorkerMetadata(metadata)
	if err != nil {
		return err
	}
	return writer.WriteFrame(workerFrame{
		Kind: workerFrameKindNetworkResponse, ID: id, Metadata: encoded, Blob1: body,
	})
}

func (session *workerParentSession) handleStorage(writer *workerFrameWriter, frame workerFrame) error {
	if !session.module.PersistentStorage {
		return fmt.Errorf("%w: worker requested storage without a grant", errWorkerProtocol)
	}
	session.storageCalls++
	if session.storageCalls > maxWorkerStorageCallsPerAction {
		return fmt.Errorf("%w: worker exceeded the storage call limit", errWorkerProtocol)
	}
	if len(frame.Blob2) != 0 || !utf8.Valid(frame.Blob1) {
		return fmt.Errorf("%w: invalid storage value", errWorkerProtocol)
	}
	var metadata workerStorageRequestMetadata
	if err := unmarshalWorkerMetadata(frame.Metadata, &metadata); err != nil {
		return err
	}
	response := workerStorageResponseMetadata{}
	var value []byte
	switch metadata.Operation {
	case "get":
		if len(frame.Blob1) != 0 {
			return fmt.Errorf("%w: storage get has a value", errWorkerProtocol)
		}
		stored, exists := session.storage.get(metadata.Key)
		response.OK, response.Exists = true, exists
		if exists {
			value = []byte(stored)
		}
	case "set":
		response.OK = session.storage.set(metadata.Key, string(frame.Blob1))
	case "delete":
		if len(frame.Blob1) != 0 {
			return fmt.Errorf("%w: storage delete has a value", errWorkerProtocol)
		}
		response.OK = session.storage.remove(metadata.Key)
	case "clear":
		if metadata.Key != "" || len(frame.Blob1) != 0 {
			return fmt.Errorf("%w: storage clear has arguments", errWorkerProtocol)
		}
		response.OK = session.storage.clear()
	default:
		return fmt.Errorf("%w: unknown storage operation %q", errWorkerProtocol, metadata.Operation)
	}
	encoded, err := marshalWorkerMetadata(response)
	if err != nil {
		return err
	}
	return writer.WriteFrame(workerFrame{
		Kind: workerFrameKindStorageResponse, ID: frame.ID, Metadata: encoded, Blob1: value,
	})
}

func (session *workerParentSession) handleLog(writer *workerFrameWriter, frame workerFrame) error {
	if len(frame.Blob1)+len(frame.Blob2) != 0 {
		return fmt.Errorf("%w: log frame has blobs", errWorkerProtocol)
	}
	var metadata workerLogMetadata
	if err := unmarshalWorkerMetadata(frame.Metadata, &metadata); err != nil {
		return err
	}
	if metadata.Level != "info" && metadata.Level != "warn" && metadata.Level != "error" {
		return fmt.Errorf("%w: invalid log level", errWorkerProtocol)
	}
	if len(metadata.Message) > maxEngineLogMessageBytes {
		return fmt.Errorf("%w: invalid log message", errWorkerProtocol)
	}
	session.logCount++
	if session.logCount > maxWorkerLogCallbacksPerAction {
		return fmt.Errorf("%w: worker exceeded the log callback limit", errWorkerProtocol)
	}
	if session.runtime != nil && metadata.Message != "" && engineLogPublishingEnabled(session.runtime.logs) {
		session.runtime.logs.Publish(EngineLog{
			Source: "script", Level: metadata.Level,
			Extension: session.module.ID, Action: session.rule.ID, Phase: session.rule.Phase,
			URL: sanitizeEngineLogURL(session.request.URL), ScriptDigest: session.rule.ScriptDigest,
			Message: metadata.Message,
		})
	}
	encoded, err := marshalWorkerMetadata(workerAckMetadata{OK: true})
	if err != nil {
		return err
	}
	return writer.WriteFrame(workerFrame{Kind: workerFrameKindLogAck, ID: frame.ID, Metadata: encoded})
}

type workerStorageSession struct {
	runtime  *scriptRuntime
	moduleID string
	commits  int
}

func (session *workerStorageSession) get(key string) (string, bool) {
	if session.runtime == nil || len(key) == 0 || len(key) > maxPersistentKeyBytes {
		return "", false
	}
	snapshot := session.runtime.persistent.Load()
	if snapshot == nil {
		return "", false
	}
	value, exists := snapshot.modules[session.moduleID][key]
	return value, exists
}

func (session *workerStorageSession) spend() bool {
	session.commits++
	return session.commits <= maxPersistentCommitsPerAction
}

func (session *workerStorageSession) set(key, value string) bool {
	runtimeState := session.runtime
	if runtimeState == nil || len(key) == 0 || len(key) > maxPersistentKeyBytes || len(value) > maxPersistentValueBytes {
		return false
	}
	runtimeState.persistentWriteMu.Lock()
	defer runtimeState.persistentWriteMu.Unlock()
	if runtimeState.persistentLoadErr != nil {
		return false
	}
	current := runtimeState.persistent.Load()
	bucket := current.modules[session.moduleID]
	if len(bucket) >= maxPersistentKeys {
		if _, exists := bucket[key]; !exists {
			return false
		}
	}
	if previous, exists := bucket[key]; exists && previous == value {
		return true
	}
	if !session.spend() {
		return false
	}
	nextModules := clonePersistentModules(current.modules)
	nextBucket := clonePersistentBucket(bucket)
	nextBucket[key] = value
	if persistentBucketBytes(nextBucket) > maxPersistentModuleBytes {
		runtimeState.reportStorageQuota(session.moduleID, "extension storage quota exhausted")
		return false
	}
	nextModules[session.moduleID] = nextBucket
	next := &persistentSnapshot{modules: nextModules}
	if err := runtimeState.persistPersistent(next); err != nil {
		runtimeState.reportStorageQuota(session.moduleID, err.Error())
		return false
	}
	runtimeState.persistent.Store(next)
	return true
}

func (session *workerStorageSession) remove(key string) bool {
	runtimeState := session.runtime
	if runtimeState == nil || len(key) == 0 || len(key) > maxPersistentKeyBytes {
		return false
	}
	runtimeState.persistentWriteMu.Lock()
	defer runtimeState.persistentWriteMu.Unlock()
	if runtimeState.persistentLoadErr != nil {
		return false
	}
	current := runtimeState.persistent.Load()
	bucket := current.modules[session.moduleID]
	if _, exists := bucket[key]; !exists || !session.spend() {
		return false
	}
	nextModules := clonePersistentModules(current.modules)
	nextBucket := clonePersistentBucket(bucket)
	delete(nextBucket, key)
	nextModules[session.moduleID] = nextBucket
	next := &persistentSnapshot{modules: nextModules}
	if err := runtimeState.persistPersistent(next); err != nil {
		return false
	}
	runtimeState.persistent.Store(next)
	return true
}

func (session *workerStorageSession) clear() bool {
	runtimeState := session.runtime
	if runtimeState == nil {
		return false
	}
	runtimeState.persistentWriteMu.Lock()
	defer runtimeState.persistentWriteMu.Unlock()
	if runtimeState.persistentLoadErr != nil {
		return false
	}
	current := runtimeState.persistent.Load()
	if _, exists := current.modules[session.moduleID]; !exists {
		return true
	}
	if !session.spend() {
		return false
	}
	nextModules := clonePersistentModules(current.modules)
	delete(nextModules, session.moduleID)
	next := &persistentSnapshot{modules: nextModules}
	if err := runtimeState.persistPersistent(next); err != nil {
		return false
	}
	runtimeState.persistent.Store(next)
	return true
}
