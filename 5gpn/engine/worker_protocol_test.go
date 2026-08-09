package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestWorkerMetadataMapCapacityDoesNotTrustDeclaredCount(t *testing.T) {
	for _, declared := range []int{17, 1024, workerMetadataMaxMapItems} {
		if got := workerMetadataMapCapacity(declared); got != 16 {
			t.Fatalf("capacity(%d) = %d, want 16", declared, got)
		}
	}
}

func TestNetworkResponseMetadataHasIndependentCombinedHeaderBudget(t *testing.T) {
	request, _ := workerLimitsForFrame(workerFrameKindNetworkRequest)
	response, _ := workerLimitsForFrame(workerFrameKindNetworkResponse)
	if request.metadata != 128<<10 {
		t.Fatalf("network request metadata limit = %d", request.metadata)
	}
	if response.metadata != 256<<10 {
		t.Fatalf("network response metadata limit = %d", response.metadata)
	}
}

type workerProtocolTestMetadata struct {
	Name  string `msgpack:"name"`
	Count int    `msgpack:"count"`
}

func TestWorkerFrameRoundTripKeepsMetadataAndRawBlobs(t *testing.T) {
	metadata, err := marshalWorkerMetadata(workerProtocolTestMetadata{Name: "action", Count: 7})
	if err != nil {
		t.Fatalf("marshalWorkerMetadata: %v", err)
	}
	want := workerFrame{
		Kind: workerFrameKindExecute, ID: 1, Metadata: metadata,
		Blob1: []byte{0, 1, 2, 0xff}, Blob2: []byte("response"),
	}
	var wire bytes.Buffer
	if err := writeWorkerFrame(&wire, want); err != nil {
		t.Fatalf("writeWorkerFrame: %v", err)
	}
	got, err := readWorkerFrame(&wire)
	if err != nil {
		t.Fatalf("readWorkerFrame: %v", err)
	}
	if got.Kind != want.Kind || got.ID != want.ID ||
		!bytes.Equal(got.Metadata, want.Metadata) ||
		!bytes.Equal(got.Blob1, want.Blob1) || !bytes.Equal(got.Blob2, want.Blob2) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	var decoded workerProtocolTestMetadata
	if err := unmarshalWorkerMetadata(got.Metadata, &decoded); err != nil {
		t.Fatalf("unmarshalWorkerMetadata: %v", err)
	}
	if decoded.Name != "action" || decoded.Count != 7 {
		t.Fatalf("decoded metadata = %+v", decoded)
	}
}

func TestWorkerFrameHeaderIsStableAndBigEndian(t *testing.T) {
	metadata, err := marshalWorkerMetadata(map[string]any{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	frame := workerFrame{Kind: workerFrameKindNetworkRequest, ID: 0x0102030405060708, Metadata: metadata, Blob1: []byte("body")}
	var wire bytes.Buffer
	if err := writeWorkerFrame(&wire, frame); err != nil {
		t.Fatal(err)
	}
	header := wire.Bytes()[:workerFrameHeaderBytes]
	if string(header[0:4]) != "5GPW" || binary.BigEndian.Uint16(header[4:6]) != 1 ||
		workerFrameKind(binary.BigEndian.Uint16(header[6:8])) != workerFrameKindNetworkRequest ||
		binary.BigEndian.Uint32(header[8:12]) != 0 || binary.BigEndian.Uint64(header[12:20]) != frame.ID ||
		binary.BigEndian.Uint32(header[20:24]) != uint32(len(metadata)) ||
		binary.BigEndian.Uint64(header[24:32]) != 4 || binary.BigEndian.Uint64(header[32:40]) != 0 {
		t.Fatalf("unexpected header: %x", header)
	}
}

func TestWorkerFrameRejectsUnknownHeaderFieldsBeforePayload(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "magic", mutate: func(header []byte) { header[0] = 'X' }},
		{name: "version", mutate: func(header []byte) { binary.BigEndian.PutUint16(header[4:6], workerProtocolVersion+1) }},
		{name: "kind", mutate: func(header []byte) { binary.BigEndian.PutUint16(header[6:8], 0xffff) }},
		{name: "flags", mutate: func(header []byte) { binary.BigEndian.PutUint32(header[8:12], 1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := workerTestHeader(workerFrameKindLog, 2, 0, 0, 0)
			test.mutate(header)
			payload := []byte("must remain unread")
			reader := bytes.NewReader(append(header, payload...))
			if _, err := readWorkerFrame(reader); !errors.Is(err, errWorkerProtocol) {
				t.Fatalf("error = %v, want protocol error", err)
			}
			if reader.Len() != len(payload) {
				t.Fatalf("reader consumed %d payload bytes before rejecting header", len(payload)-reader.Len())
			}
		})
	}
}

func TestWorkerFrameRejectsPerKindLengthsBeforeAllocation(t *testing.T) {
	tests := []struct {
		name     string
		kind     workerFrameKind
		id       uint64
		metadata uint64
		blob1    uint64
		blob2    uint64
	}{
		{name: "gate metadata", kind: workerFrameKindGate, metadata: 1},
		{name: "ready blob", kind: workerFrameKindReady, blob1: 1},
		{name: "validate config", kind: workerFrameKindValidate, id: 1, blob1: 16<<20 + 1},
		{name: "execute metadata", kind: workerFrameKindExecute, id: 1, metadata: 2<<20 + 1},
		{name: "execute body", kind: workerFrameKindExecute, id: 1, blob2: 64<<20 + 1},
		{name: "network body", kind: workerFrameKindNetworkRequest, id: 2, blob1: 1<<20 + 1},
		{name: "storage value", kind: workerFrameKindStorageResponse, id: 2, blob1: 64<<10 + 1},
		{name: "log metadata", kind: workerFrameKindLog, id: 2, metadata: 16<<10 + 1},
		{name: "result second blob", kind: workerFrameKindResult, id: 1, blob2: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := workerTestHeader(test.kind, test.id, test.metadata, test.blob1, test.blob2)
			payload := []byte("must remain unread")
			reader := bytes.NewReader(append(header, payload...))
			if _, err := readWorkerFrame(reader); !errors.Is(err, errWorkerFrameLimit) {
				t.Fatalf("error = %v, want frame limit", err)
			}
			if reader.Len() != len(payload) {
				t.Fatalf("reader consumed payload before rejecting lengths")
			}
		})
	}
}

func TestWorkerFrameCorrelationNamespacesAreStrict(t *testing.T) {
	tests := []struct {
		name string
		kind workerFrameKind
		id   uint64
	}{
		{name: "gate nonzero", kind: workerFrameKindGate, id: 1},
		{name: "ready nonzero", kind: workerFrameKindReady, id: 2},
		{name: "execute zero", kind: workerFrameKindExecute, id: 0},
		{name: "execute even", kind: workerFrameKindExecute, id: 2},
		{name: "result even", kind: workerFrameKindResult, id: 2},
		{name: "network zero", kind: workerFrameKindNetworkRequest, id: 0},
		{name: "network odd", kind: workerFrameKindNetworkResponse, id: 1},
		{name: "storage odd", kind: workerFrameKindStorageRequest, id: 3},
		{name: "log odd", kind: workerFrameKindLogAck, id: 5},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateWorkerFrameID(test.kind, test.id); !errors.Is(err, errWorkerProtocol) {
				t.Fatalf("error = %v, want protocol error", err)
			}
		})
	}
	for _, valid := range []workerFrame{
		{Kind: workerFrameKindGate},
		{Kind: workerFrameKindReady},
		{Kind: workerFrameKindProbe, ID: 1},
		{Kind: workerFrameKindValidate, ID: 3},
		{Kind: workerFrameKindExecute, ID: 5},
		{Kind: workerFrameKindNetworkRequest, ID: 2},
		{Kind: workerFrameKindStorageResponse, ID: 4},
		{Kind: workerFrameKindLog, ID: 6},
		{Kind: workerFrameKindResult, ID: 7},
		{Kind: workerFrameKindError, ID: 9},
	} {
		if err := validateWorkerFrameID(valid.Kind, valid.ID); err != nil {
			t.Errorf("valid %s/%d: %v", valid.Kind, valid.ID, err)
		}
	}
}

func TestWorkerFrameReaderRejectsDuplicateIDBeforePayload(t *testing.T) {
	first := workerFrame{Kind: workerFrameKindNetworkRequest, ID: 2}
	secondMetadata, err := marshalWorkerMetadata(map[string]any{"second": true})
	if err != nil {
		t.Fatal(err)
	}
	second := workerFrame{Kind: workerFrameKindNetworkRequest, ID: 2, Metadata: secondMetadata, Blob1: []byte("unread")}
	var wire bytes.Buffer
	if err := writeWorkerFrame(&wire, first); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkerFrame(&wire, second); err != nil {
		t.Fatal(err)
	}
	reader := newWorkerFrameReader(&wire)
	if _, err := reader.ReadFrame(); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	remainingBefore := wire.Len()
	if _, err := reader.ReadFrame(); !errors.Is(err, errWorkerFrameDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}
	wantRemaining := remainingBefore - workerFrameHeaderBytes
	if wire.Len() != wantRemaining {
		t.Fatalf("duplicate consumed payload: remaining %d, want %d", wire.Len(), wantRemaining)
	}
}

func TestWorkerFrameWriterRejectsDuplicateID(t *testing.T) {
	var wire bytes.Buffer
	writer := newWorkerFrameWriter(&wire)
	if err := writer.WriteFrame(workerFrame{Kind: workerFrameKindNetworkRequest, ID: 2}); err != nil {
		t.Fatal(err)
	}
	written := wire.Len()
	if err := writer.WriteFrame(workerFrame{Kind: workerFrameKindNetworkResponse, ID: 2}); !errors.Is(err, errWorkerFrameDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}
	if wire.Len() != written {
		t.Fatal("duplicate writer changed the stream")
	}
}

func TestWorkerFrameReaderRejectsTruncation(t *testing.T) {
	header := workerTestHeader(workerFrameKindExecute, 1, 2, 2, 2)
	for cut := 1; cut < len(header); cut++ {
		if _, err := readWorkerFrame(bytes.NewReader(header[:cut])); !errors.Is(err, errWorkerFrameTruncated) {
			t.Fatalf("header cut %d error = %v", cut, err)
		}
	}
	if _, err := readWorkerFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("empty stream error = %v, want EOF", err)
	}

	metadata := []byte{0xc0, 0xc0}
	if _, err := readWorkerFrame(bytes.NewReader(append(header, metadata[:1]...))); !errors.Is(err, errWorkerFrameTruncated) {
		t.Fatalf("metadata truncation error = %v", err)
	}

	validMetadata, err := marshalWorkerMetadata(map[string]any{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	header = workerTestHeader(workerFrameKindExecute, 1, uint64(len(validMetadata)), 2, 2)
	wire := append(header, validMetadata...)
	wire = append(wire, 'x')
	if _, err := readWorkerFrame(bytes.NewReader(wire)); !errors.Is(err, errWorkerFrameTruncated) {
		t.Fatalf("blob 1 truncation error = %v", err)
	}

	wire = append(header, validMetadata...)
	wire = append(wire, 'a', 'b', 'x')
	if _, err := readWorkerFrame(bytes.NewReader(wire)); !errors.Is(err, errWorkerFrameTruncated) {
		t.Fatalf("blob 2 truncation error = %v", err)
	}
}

func TestWorkerFrameRejectsInvalidMetadataBeforeBlobAllocation(t *testing.T) {
	duplicate := []byte{0x82, 0xa1, 'a', 0x01, 0xa1, 'a', 0x02}
	header := workerTestHeader(workerFrameKindExecute, 1, uint64(len(duplicate)), 1, 0)
	wire := bytes.NewReader(append(append(header, duplicate...), 'x'))
	if _, err := readWorkerFrame(wire); !errors.Is(err, errWorkerMetadataInvalid) {
		t.Fatalf("error = %v, want invalid metadata", err)
	}
	if wire.Len() != 1 {
		t.Fatal("reader allocated or consumed blob after invalid metadata")
	}
}

func TestWorkerMetadataRejectsDuplicateUnknownAndTrailingFields(t *testing.T) {
	duplicate := []byte{0x82, 0xa1, 'a', 0x01, 0xa1, 'a', 0x02}
	if err := validateWorkerMetadata(duplicate); !errors.Is(err, errWorkerMetadataInvalid) || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}

	trailing, err := marshalWorkerMetadata(workerProtocolTestMetadata{Name: "valid"})
	if err != nil {
		t.Fatal(err)
	}
	trailing = append(trailing, 0xc0)
	if err := validateWorkerMetadata(trailing); !errors.Is(err, errWorkerMetadataInvalid) || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing error = %v", err)
	}

	unknown, err := msgpack.Marshal(map[string]any{"name": "valid", "extra": true})
	if err != nil {
		t.Fatal(err)
	}
	var target workerProtocolTestMetadata
	if err := unmarshalWorkerMetadata(unknown, &target); !errors.Is(err, errWorkerMetadataInvalid) || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown-field error = %v", err)
	}
}

func TestWorkerMetadataRejectsMaliciousContainerDeclarationsWithoutAllocatingThem(t *testing.T) {
	tests := [][]byte{
		{0xdd, 0xff, 0xff, 0xff, 0xff},
		{0xdf, 0xff, 0xff, 0xff, 0xff},
		{0xdb, 0xff, 0xff, 0xff, 0xff},
		{0xc9, 0xff, 0xff, 0xff, 0xff},
	}
	for _, body := range tests {
		if err := validateWorkerMetadata(body); !errors.Is(err, errWorkerMetadataInvalid) {
			t.Errorf("metadata %x error = %v", body, err)
		}
	}
}

func TestWorkerMetadataRejectsDepthNonStringKeysAndInvalidUTF8(t *testing.T) {
	deep := bytes.Repeat([]byte{0x91}, workerMetadataMaxDepth+1)
	deep = append(deep, 0xc0)
	if err := validateWorkerMetadata(deep); !errors.Is(err, errWorkerMetadataInvalid) || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("depth error = %v", err)
	}
	if err := validateWorkerMetadata([]byte{0x81, 0x01, 0xc0}); !errors.Is(err, errWorkerMetadataInvalid) || !strings.Contains(err.Error(), "not a string") {
		t.Fatalf("map key error = %v", err)
	}
	if err := validateWorkerMetadata([]byte{0xa1, 0xff}); !errors.Is(err, errWorkerMetadataInvalid) || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("UTF-8 error = %v", err)
	}
}

func TestWorkerFrameWriterRejectsInvalidFrameBeforeWriting(t *testing.T) {
	tests := []workerFrame{
		{Kind: 0xffff, ID: 1},
		{Kind: workerFrameKindGate, ID: 1},
		{Kind: workerFrameKindGate, Blob1: []byte{1}},
		{Kind: workerFrameKindLog, ID: 2, Metadata: []byte{0x81}},
	}
	for _, frame := range tests {
		var wire bytes.Buffer
		if err := writeWorkerFrame(&wire, frame); err == nil {
			t.Fatalf("writeWorkerFrame(%+v) succeeded", frame)
		}
		if wire.Len() != 0 {
			t.Fatalf("invalid frame wrote %d bytes", wire.Len())
		}
	}
}

func TestWorkerFrameReaderAndWriterBoundSessionState(t *testing.T) {
	var wire bytes.Buffer
	writer := newWorkerFrameWriter(&wire)
	for index := 0; index < workerProtocolMaxFrames; index++ {
		id := uint64(2 * (index + 1))
		if err := writer.WriteFrame(workerFrame{Kind: workerFrameKindLog, ID: id}); err != nil {
			t.Fatalf("frame %d: %v", index, err)
		}
	}
	if err := writer.WriteFrame(workerFrame{Kind: workerFrameKindLog, ID: 2 * (workerProtocolMaxFrames + 1)}); !errors.Is(err, errWorkerFrameLimit) {
		t.Fatalf("writer frame limit error = %v", err)
	}

	reader := newWorkerFrameReader(&wire)
	for index := 0; index < workerProtocolMaxFrames; index++ {
		if _, err := reader.ReadFrame(); err != nil {
			t.Fatalf("read frame %d: %v", index, err)
		}
	}
	extra := workerTestHeader(workerFrameKindLog, 2*(workerProtocolMaxFrames+1), 0, 0, 0)
	reader.reader = io.MultiReader(reader.reader, bytes.NewReader(extra))
	if _, err := reader.ReadFrame(); !errors.Is(err, errWorkerFrameLimit) {
		t.Fatalf("reader frame limit error = %v", err)
	}
}

func workerTestHeader(kind workerFrameKind, id, metadata, blob1, blob2 uint64) []byte {
	header := make([]byte, workerFrameHeaderBytes)
	copy(header[0:4], workerFrameMagic[:])
	binary.BigEndian.PutUint16(header[4:6], workerProtocolVersion)
	binary.BigEndian.PutUint16(header[6:8], uint16(kind))
	binary.BigEndian.PutUint64(header[12:20], id)
	binary.BigEndian.PutUint32(header[20:24], uint32(metadata))
	binary.BigEndian.PutUint64(header[24:32], blob1)
	binary.BigEndian.PutUint64(header[32:40], blob2)
	return header
}
