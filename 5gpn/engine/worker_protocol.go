package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/vmihailenco/msgpack/v5/msgpcode"
)

// The extension worker protocol is private to two invocations of the same
// binary. It is nevertheless treated as an untrusted boundary: a worker is the
// process that just ran publisher-supplied code, and a malformed length must be
// rejected before it can cause a parent allocation.
const (
	workerProtocolVersion   = uint16(1)
	workerFrameHeaderBytes  = 40
	workerProtocolMaxFrames = 512

	workerMetadataMaxDepth      = 64
	workerMetadataMaxNodes      = 128 << 10
	workerMetadataMaxArrayItems = 64 << 10
	workerMetadataMaxMapItems   = 16 << 10
	// HTTP field names live in metadata maps and are bounded by the existing
	// 64 KiB header-block limit, not by the much smaller extension setting-key
	// limit. Keep the protocol at that same boundary.
	workerMetadataMaxKeyBytes      = 64 << 10
	workerMetadataMaxTotalKeyBytes = 256 << 10
)

var workerFrameMagic = [4]byte{'5', 'G', 'P', 'W'}

var (
	errWorkerProtocol        = errors.New("extension worker protocol error")
	errWorkerFrameTruncated  = fmt.Errorf("%w: frame is truncated", errWorkerProtocol)
	errWorkerFrameDuplicate  = fmt.Errorf("%w: correlation id is duplicated", errWorkerProtocol)
	errWorkerFrameLimit      = fmt.Errorf("%w: frame exceeds its limit", errWorkerProtocol)
	errWorkerMetadataInvalid = fmt.Errorf("%w: metadata is invalid", errWorkerProtocol)
)

type workerFrameKind uint16

const (
	workerFrameKindGate workerFrameKind = iota + 1
	workerFrameKindReady
	workerFrameKindProbe
	workerFrameKindValidate
	workerFrameKindExecute
	workerFrameKindNetworkRequest
	workerFrameKindNetworkResponse
	workerFrameKindStorageRequest
	workerFrameKindStorageResponse
	workerFrameKindLog
	workerFrameKindLogAck
	workerFrameKindResult
	workerFrameKindError
)

func (kind workerFrameKind) String() string {
	switch kind {
	case workerFrameKindGate:
		return "gate"
	case workerFrameKindReady:
		return "ready"
	case workerFrameKindProbe:
		return "probe"
	case workerFrameKindValidate:
		return "validate"
	case workerFrameKindExecute:
		return "execute"
	case workerFrameKindNetworkRequest:
		return "network-request"
	case workerFrameKindNetworkResponse:
		return "network-response"
	case workerFrameKindStorageRequest:
		return "storage-request"
	case workerFrameKindStorageResponse:
		return "storage-response"
	case workerFrameKindLog:
		return "log"
	case workerFrameKindLogAck:
		return "log-ack"
	case workerFrameKindResult:
		return "result"
	case workerFrameKindError:
		return "error"
	default:
		return fmt.Sprintf("kind-%d", uint16(kind))
	}
}

type workerFrame struct {
	Kind     workerFrameKind
	ID       uint64
	Metadata []byte
	Blob1    []byte
	Blob2    []byte
}

type workerFrameLimits struct {
	metadata uint64
	blob1    uint64
	blob2    uint64
}

func workerLimitsForFrame(kind workerFrameKind) (workerFrameLimits, bool) {
	switch kind {
	case workerFrameKindGate:
		return workerFrameLimits{}, true
	case workerFrameKindReady, workerFrameKindProbe:
		return workerFrameLimits{metadata: 4 << 10}, true
	case workerFrameKindValidate:
		return workerFrameLimits{metadata: 64 << 10, blob1: 16 << 20}, true
	case workerFrameKindExecute:
		return workerFrameLimits{metadata: 2 << 20, blob1: 64 << 20, blob2: 64 << 20}, true
	case workerFrameKindNetworkRequest:
		return workerFrameLimits{metadata: 128 << 10, blob1: 1 << 20}, true
	case workerFrameKindNetworkResponse:
		return workerFrameLimits{metadata: 256 << 10, blob1: 1 << 20}, true
	case workerFrameKindStorageRequest, workerFrameKindStorageResponse:
		return workerFrameLimits{metadata: 8 << 10, blob1: 64 << 10}, true
	case workerFrameKindLog:
		return workerFrameLimits{metadata: 16 << 10}, true
	case workerFrameKindLogAck:
		return workerFrameLimits{metadata: 4 << 10}, true
	case workerFrameKindResult:
		return workerFrameLimits{metadata: 256 << 10, blob1: 64 << 20}, true
	case workerFrameKindError:
		return workerFrameLimits{metadata: 64 << 10}, true
	default:
		return workerFrameLimits{}, false
	}
}

// Parent-originated operations and their terminal replies use odd IDs. Child
// callback operations and their replies use non-zero even IDs. READY and GATE
// are the sole uncorrelated frames and use zero. The disjoint namespaces make
// an echoed reply ID unique on each unidirectional pipe too.
func validateWorkerFrameID(kind workerFrameKind, id uint64) error {
	switch kind {
	case workerFrameKindGate, workerFrameKindReady:
		if id != 0 {
			return fmt.Errorf("%w: %s frame must use correlation id zero", errWorkerProtocol, kind)
		}
	case workerFrameKindProbe, workerFrameKindValidate, workerFrameKindExecute,
		workerFrameKindResult, workerFrameKindError:
		if id == 0 || id&1 == 0 {
			return fmt.Errorf("%w: %s frame must use a non-zero odd correlation id", errWorkerProtocol, kind)
		}
	case workerFrameKindNetworkRequest, workerFrameKindNetworkResponse,
		workerFrameKindStorageRequest, workerFrameKindStorageResponse,
		workerFrameKindLog, workerFrameKindLogAck:
		if id == 0 || id&1 != 0 {
			return fmt.Errorf("%w: %s frame must use a non-zero even correlation id", errWorkerProtocol, kind)
		}
	default:
		return fmt.Errorf("%w: unknown frame kind %d", errWorkerProtocol, uint16(kind))
	}
	return nil
}

func validateWorkerFrame(frame workerFrame) error {
	limits, known := workerLimitsForFrame(frame.Kind)
	if !known {
		return fmt.Errorf("%w: unknown frame kind %d", errWorkerProtocol, uint16(frame.Kind))
	}
	if err := validateWorkerFrameID(frame.Kind, frame.ID); err != nil {
		return err
	}
	if uint64(len(frame.Metadata)) > limits.metadata ||
		uint64(len(frame.Blob1)) > limits.blob1 ||
		uint64(len(frame.Blob2)) > limits.blob2 {
		return fmt.Errorf("%w: %s frame has metadata/blob lengths %d/%d/%d", errWorkerFrameLimit,
			frame.Kind, len(frame.Metadata), len(frame.Blob1), len(frame.Blob2))
	}
	if len(frame.Metadata) > 0 {
		if err := validateWorkerMetadata(frame.Metadata); err != nil {
			return err
		}
	}
	return nil
}

// workerFrameReader retains the IDs already observed on one direction of one
// worker pipe. A caller must keep one reader for the complete one-shot session;
// constructing a reader per frame would discard duplicate detection.
type workerFrameReader struct {
	reader io.Reader
	seen   map[uint64]struct{}
}

func newWorkerFrameReader(reader io.Reader) *workerFrameReader {
	return &workerFrameReader{reader: reader, seen: make(map[uint64]struct{})}
}

func (reader *workerFrameReader) ReadFrame() (workerFrame, error) {
	var header [workerFrameHeaderBytes]byte
	read, err := io.ReadFull(reader.reader, header[:])
	if err != nil {
		if read == 0 && errors.Is(err, io.EOF) {
			return workerFrame{}, io.EOF
		}
		return workerFrame{}, fmt.Errorf("%w: header: %v", errWorkerFrameTruncated, err)
	}

	kind, id, metadataBytes, blob1Bytes, blob2Bytes, err := decodeWorkerFrameHeader(header[:])
	if err != nil {
		return workerFrame{}, err
	}
	if _, duplicate := reader.seen[id]; duplicate {
		return workerFrame{}, fmt.Errorf("%w: %d", errWorkerFrameDuplicate, id)
	}
	if len(reader.seen) >= workerProtocolMaxFrames {
		return workerFrame{}, fmt.Errorf("%w: more than %d frames", errWorkerFrameLimit, workerProtocolMaxFrames)
	}

	frame := workerFrame{Kind: kind, ID: id}
	frame.Metadata, err = readWorkerFramePart(reader.reader, metadataBytes, "metadata")
	if err != nil {
		return workerFrame{}, err
	}
	if len(frame.Metadata) > 0 {
		if err := validateWorkerMetadata(frame.Metadata); err != nil {
			return workerFrame{}, err
		}
	}
	frame.Blob1, err = readWorkerFramePart(reader.reader, blob1Bytes, "blob 1")
	if err != nil {
		return workerFrame{}, err
	}
	frame.Blob2, err = readWorkerFramePart(reader.reader, blob2Bytes, "blob 2")
	if err != nil {
		return workerFrame{}, err
	}
	reader.seen[id] = struct{}{}
	return frame, nil
}

// readWorkerFrame reads one standalone frame. Brokers that read more than one
// frame must retain a workerFrameReader so duplicate IDs stay fenced.
func readWorkerFrame(reader io.Reader) (workerFrame, error) {
	return newWorkerFrameReader(reader).ReadFrame()
}

type workerFrameWriter struct {
	mu     sync.Mutex
	writer io.Writer
	seen   map[uint64]struct{}
}

func newWorkerFrameWriter(writer io.Writer) *workerFrameWriter {
	return &workerFrameWriter{writer: writer, seen: make(map[uint64]struct{})}
}

// WriteFrame serializes concurrent callback replies and also refuses an
// accidental duplicate before it corrupts the peer's session state.
func (writer *workerFrameWriter) WriteFrame(frame workerFrame) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if err := validateWorkerFrame(frame); err != nil {
		return err
	}
	if _, duplicate := writer.seen[frame.ID]; duplicate {
		return fmt.Errorf("%w: %d", errWorkerFrameDuplicate, frame.ID)
	}
	if len(writer.seen) >= workerProtocolMaxFrames {
		return fmt.Errorf("%w: more than %d frames", errWorkerFrameLimit, workerProtocolMaxFrames)
	}
	if err := writeWorkerFrameValidated(writer.writer, frame); err != nil {
		return err
	}
	writer.seen[frame.ID] = struct{}{}
	return nil
}

func writeWorkerFrame(writer io.Writer, frame workerFrame) error {
	if err := validateWorkerFrame(frame); err != nil {
		return err
	}
	return writeWorkerFrameValidated(writer, frame)
}

func writeWorkerFrameValidated(writer io.Writer, frame workerFrame) error {
	var header [workerFrameHeaderBytes]byte
	copy(header[0:4], workerFrameMagic[:])
	binary.BigEndian.PutUint16(header[4:6], workerProtocolVersion)
	binary.BigEndian.PutUint16(header[6:8], uint16(frame.Kind))
	// Bytes 8:12 are protocol flags. Version 1 defines none, so zero is the
	// only legal value and the reader rejects every other bit.
	binary.BigEndian.PutUint32(header[8:12], 0)
	binary.BigEndian.PutUint64(header[12:20], frame.ID)
	binary.BigEndian.PutUint32(header[20:24], uint32(len(frame.Metadata)))
	binary.BigEndian.PutUint64(header[24:32], uint64(len(frame.Blob1)))
	binary.BigEndian.PutUint64(header[32:40], uint64(len(frame.Blob2)))

	for _, part := range [][]byte{header[:], frame.Metadata, frame.Blob1, frame.Blob2} {
		if err := writeWorkerBytes(writer, part); err != nil {
			return fmt.Errorf("%w: write frame: %v", errWorkerProtocol, err)
		}
	}
	return nil
}

func decodeWorkerFrameHeader(header []byte) (workerFrameKind, uint64, uint64, uint64, uint64, error) {
	if len(header) != workerFrameHeaderBytes {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: header size %d", errWorkerProtocol, len(header))
	}
	if !bytes.Equal(header[0:4], workerFrameMagic[:]) {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: invalid frame magic", errWorkerProtocol)
	}
	if version := binary.BigEndian.Uint16(header[4:6]); version != workerProtocolVersion {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: unsupported version %d", errWorkerProtocol, version)
	}
	if flags := binary.BigEndian.Uint32(header[8:12]); flags != 0 {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: unsupported flags 0x%x", errWorkerProtocol, flags)
	}

	kind := workerFrameKind(binary.BigEndian.Uint16(header[6:8]))
	limits, known := workerLimitsForFrame(kind)
	if !known {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: unknown frame kind %d", errWorkerProtocol, uint16(kind))
	}
	id := binary.BigEndian.Uint64(header[12:20])
	if err := validateWorkerFrameID(kind, id); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	metadataBytes := uint64(binary.BigEndian.Uint32(header[20:24]))
	blob1Bytes := binary.BigEndian.Uint64(header[24:32])
	blob2Bytes := binary.BigEndian.Uint64(header[32:40])
	if metadataBytes > limits.metadata || blob1Bytes > limits.blob1 || blob2Bytes > limits.blob2 {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: %s frame has metadata/blob lengths %d/%d/%d",
			errWorkerFrameLimit, kind, metadataBytes, blob1Bytes, blob2Bytes)
	}
	return kind, id, metadataBytes, blob1Bytes, blob2Bytes, nil
}

func readWorkerFramePart(reader io.Reader, length uint64, name string) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	maxInt := uint64(^uint(0) >> 1)
	if length > maxInt {
		return nil, fmt.Errorf("%w: %s length %d cannot be represented", errWorkerFrameLimit, name, length)
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errWorkerFrameTruncated, name, err)
	}
	return body, nil
}

func writeWorkerBytes(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		written, err := writer.Write(body)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(body) {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

func marshalWorkerMetadata(value any) ([]byte, error) {
	body, err := msgpack.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", errWorkerMetadataInvalid, err)
	}
	if err := validateWorkerMetadata(body); err != nil {
		return nil, err
	}
	return body, nil
}

// unmarshalWorkerMetadata performs a syntax pass before the typed decode. The
// syntax pass rejects duplicate keys, excessive container declarations and
// trailing values without trusting msgpack's allocation decisions. The typed
// pass then rejects fields the selected operation schema does not know.
func unmarshalWorkerMetadata(body []byte, target any) error {
	if target == nil {
		return fmt.Errorf("%w: decode target is nil", errWorkerMetadataInvalid)
	}
	if len(body) == 0 {
		return fmt.Errorf("%w: metadata is empty", errWorkerMetadataInvalid)
	}
	if err := validateWorkerMetadata(body); err != nil {
		return err
	}
	reader := bytes.NewReader(body)
	decoder := msgpack.NewDecoder(reader)
	decoder.DisallowUnknownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode: %v", errWorkerMetadataInvalid, err)
	}
	if reader.Len() != 0 {
		return fmt.Errorf("%w: trailing data", errWorkerMetadataInvalid)
	}
	return nil
}

func validateWorkerMetadata(body []byte) error {
	if len(body) == 0 {
		return nil
	}
	nodes := 0
	keyBytes := 0
	next, err := scanWorkerMetadataValue(body, 0, 1, &nodes, &keyBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", errWorkerMetadataInvalid, err)
	}
	if next != len(body) {
		return fmt.Errorf("%w: trailing data", errWorkerMetadataInvalid)
	}
	return nil
}

func scanWorkerMetadataValue(body []byte, offset, depth int, nodes, keyBytes *int) (int, error) {
	if depth > workerMetadataMaxDepth {
		return offset, fmt.Errorf("nesting exceeds %d", workerMetadataMaxDepth)
	}
	if *nodes >= workerMetadataMaxNodes {
		return offset, fmt.Errorf("values exceed %d", workerMetadataMaxNodes)
	}
	(*nodes)++
	if offset >= len(body) {
		return offset, io.ErrUnexpectedEOF
	}
	code := body[offset]
	offset++

	switch {
	case msgpcode.IsFixedNum(code):
		return offset, nil
	case msgpcode.IsFixedString(code):
		length := uint64(code & msgpcode.FixedStrMask)
		return scanWorkerMetadataBytes(body, offset, length, true)
	case msgpcode.IsFixedArray(code):
		return scanWorkerMetadataArray(body, offset, int(code&msgpcode.FixedArrayMask), depth, nodes, keyBytes)
	case msgpcode.IsFixedMap(code):
		return scanWorkerMetadataMap(body, offset, int(code&msgpcode.FixedMapMask), depth, nodes, keyBytes)
	}

	switch code {
	case msgpcode.Nil, msgpcode.False, msgpcode.True:
		return offset, nil
	case msgpcode.Uint8, msgpcode.Int8:
		return scanWorkerMetadataFixed(body, offset, 1)
	case msgpcode.Uint16, msgpcode.Int16:
		return scanWorkerMetadataFixed(body, offset, 2)
	case msgpcode.Uint32, msgpcode.Int32, msgpcode.Float:
		return scanWorkerMetadataFixed(body, offset, 4)
	case msgpcode.Uint64, msgpcode.Int64, msgpcode.Double:
		return scanWorkerMetadataFixed(body, offset, 8)
	case msgpcode.Str8, msgpcode.Bin8:
		length, next, err := readWorkerMetadataLength(body, offset, 1)
		if err != nil {
			return offset, err
		}
		return scanWorkerMetadataBytes(body, next, length, code == msgpcode.Str8)
	case msgpcode.Str16, msgpcode.Bin16:
		length, next, err := readWorkerMetadataLength(body, offset, 2)
		if err != nil {
			return offset, err
		}
		return scanWorkerMetadataBytes(body, next, length, code == msgpcode.Str16)
	case msgpcode.Str32, msgpcode.Bin32:
		length, next, err := readWorkerMetadataLength(body, offset, 4)
		if err != nil {
			return offset, err
		}
		return scanWorkerMetadataBytes(body, next, length, code == msgpcode.Str32)
	case msgpcode.Array16, msgpcode.Array32:
		lengthBytes := 2
		if code == msgpcode.Array32 {
			lengthBytes = 4
		}
		count, next, err := readWorkerMetadataLength(body, offset, lengthBytes)
		if err != nil {
			return offset, err
		}
		if count > workerMetadataMaxArrayItems {
			return offset, fmt.Errorf("array items exceed %d", workerMetadataMaxArrayItems)
		}
		return scanWorkerMetadataArray(body, next, int(count), depth, nodes, keyBytes)
	case msgpcode.Map16, msgpcode.Map32:
		lengthBytes := 2
		if code == msgpcode.Map32 {
			lengthBytes = 4
		}
		count, next, err := readWorkerMetadataLength(body, offset, lengthBytes)
		if err != nil {
			return offset, err
		}
		if count > workerMetadataMaxMapItems {
			return offset, fmt.Errorf("map items exceed %d", workerMetadataMaxMapItems)
		}
		return scanWorkerMetadataMap(body, next, int(count), depth, nodes, keyBytes)
	case msgpcode.FixExt1, msgpcode.FixExt2, msgpcode.FixExt4, msgpcode.FixExt8,
		msgpcode.FixExt16, msgpcode.Ext8, msgpcode.Ext16, msgpcode.Ext32:
		return offset, fmt.Errorf("extension values are not permitted")
	default:
		return offset, fmt.Errorf("unknown MessagePack code 0x%x", code)
	}
}

func scanWorkerMetadataArray(body []byte, offset, count, depth int, nodes, keyBytes *int) (int, error) {
	if count > workerMetadataMaxArrayItems {
		return offset, fmt.Errorf("array items exceed %d", workerMetadataMaxArrayItems)
	}
	for index := 0; index < count; index++ {
		var err error
		offset, err = scanWorkerMetadataValue(body, offset, depth+1, nodes, keyBytes)
		if err != nil {
			return offset, err
		}
	}
	return offset, nil
}

func scanWorkerMetadataMap(body []byte, offset, count, depth int, nodes, keyBytes *int) (int, error) {
	if count > workerMetadataMaxMapItems {
		return offset, fmt.Errorf("map items exceed %d", workerMetadataMaxMapItems)
	}
	keys := make(map[string]struct{}, workerMetadataMapCapacity(count))
	for index := 0; index < count; index++ {
		if depth+1 > workerMetadataMaxDepth {
			return offset, fmt.Errorf("nesting exceeds %d", workerMetadataMaxDepth)
		}
		if *nodes >= workerMetadataMaxNodes {
			return offset, fmt.Errorf("values exceed %d", workerMetadataMaxNodes)
		}
		(*nodes)++
		key, next, err := scanWorkerMetadataKey(body, offset)
		if err != nil {
			return offset, err
		}
		if _, duplicate := keys[key]; duplicate {
			return offset, fmt.Errorf("duplicate map key %q", key)
		}
		*keyBytes += len(key)
		if *keyBytes > workerMetadataMaxTotalKeyBytes {
			return offset, fmt.Errorf("map key bytes exceed %d", workerMetadataMaxTotalKeyBytes)
		}
		keys[key] = struct{}{}
		offset, err = scanWorkerMetadataValue(body, next, depth+1, nodes, keyBytes)
		if err != nil {
			return offset, err
		}
	}
	return offset, nil
}

func workerMetadataMapCapacity(declared int) int {
	if declared < 0 {
		return 0
	}
	if declared > 16 {
		return 16
	}
	return declared
}

func scanWorkerMetadataKey(body []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(body) {
		return "", offset, io.ErrUnexpectedEOF
	}
	code := body[offset]
	offset++
	var length uint64
	switch {
	case msgpcode.IsFixedString(code):
		length = uint64(code & msgpcode.FixedStrMask)
	case code == msgpcode.Str8:
		var err error
		length, offset, err = readWorkerMetadataLength(body, offset, 1)
		if err != nil {
			return "", offset, err
		}
	case code == msgpcode.Str16:
		var err error
		length, offset, err = readWorkerMetadataLength(body, offset, 2)
		if err != nil {
			return "", offset, err
		}
	case code == msgpcode.Str32:
		var err error
		length, offset, err = readWorkerMetadataLength(body, offset, 4)
		if err != nil {
			return "", offset, err
		}
	default:
		return "", offset, fmt.Errorf("map key is not a string")
	}
	if length > workerMetadataMaxKeyBytes {
		return "", offset, fmt.Errorf("map key exceeds %d bytes", workerMetadataMaxKeyBytes)
	}
	if offset > len(body) || length > uint64(len(body)-offset) {
		return "", offset, io.ErrUnexpectedEOF
	}
	end := offset + int(length)
	if !utf8.Valid(body[offset:end]) {
		return "", offset, fmt.Errorf("map key is not valid UTF-8")
	}
	return string(body[offset:end]), end, nil
}

func scanWorkerMetadataBytes(body []byte, offset int, length uint64, text bool) (int, error) {
	if offset < 0 || offset > len(body) || length > uint64(len(body)-offset) {
		return offset, io.ErrUnexpectedEOF
	}
	end := offset + int(length)
	if text && !utf8.Valid(body[offset:end]) {
		return offset, fmt.Errorf("string is not valid UTF-8")
	}
	return end, nil
}

func scanWorkerMetadataFixed(body []byte, offset, length int) (int, error) {
	if length < 0 || offset > len(body) || length > len(body)-offset {
		return offset, io.ErrUnexpectedEOF
	}
	return offset + length, nil
}

func readWorkerMetadataLength(body []byte, offset, lengthBytes int) (uint64, int, error) {
	if lengthBytes < 0 || offset > len(body) || lengthBytes > len(body)-offset {
		return 0, offset, io.ErrUnexpectedEOF
	}
	var value uint64
	switch lengthBytes {
	case 1:
		value = uint64(body[offset])
	case 2:
		value = uint64(binary.BigEndian.Uint16(body[offset : offset+2]))
	case 4:
		value = uint64(binary.BigEndian.Uint32(body[offset : offset+4]))
	default:
		return 0, offset, fmt.Errorf("unsupported length width %d", lengthBytes)
	}
	return value, offset + lengthBytes, nil
}
