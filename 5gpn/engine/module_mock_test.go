package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	M "github.com/metacubex/http"
)

func manifestWithMock(fields string) string {
	return fmt.Sprintf(`
apiVersion: 5gpn.io/v1
kind: Extension
metadata:
  id: example.mock
  name: Mock example
  version: 1.0.0
permissions: {}
requirements: {}
traffic:
  captureHosts: [api.example.com]
actions:
  - id: mock-response
    phase: request
    match:
      hosts: [api.example.com]
    script:
      mock:
%s
      bodyMode: none
      timeoutMs: 500
      maxBodyBytes: 1024
`, fields)
}

func TestManifestImportsCamelCaseBase64Mock(t *testing.T) {
	module := parseFixture(t, manifestWithMock(`        status: 200
        headers:
          Content-Type: application/grpc
        base64Body: AAECA/8=`))

	if len(module.Scripts) != 1 || module.Scripts[0].Mock == nil {
		t.Fatalf("mock action was not imported: %+v", module.Scripts)
	}
	mock := module.Scripts[0].Mock
	if mock.Base64Body == nil || *mock.Base64Body != "AAECA/8=" {
		t.Fatalf("base64Body = %v, want the manifest value", mock.Base64Body)
	}
	if mock.Body != nil {
		t.Fatalf("body = %v, want an absent text body", mock.Body)
	}
}

func TestManifestRejectsInvalidOrAmbiguousMockBodies(t *testing.T) {
	cases := map[string]struct {
		fields string
		want   string
	}{
		"invalid standard base64": {
			fields: "        base64Body: AQ",
			want:   "base64Body is not base64",
		},
		"URL base64 is not standard base64": {
			fields: "        base64Body: _w==",
			want:   "base64Body is not base64",
		},
		"two non-empty representations": {
			fields: "        body: text\n        base64Body: dGV4dA==",
			want:   "declares both body and base64Body",
		},
		"two explicitly empty representations": {
			fields: `        body: ""
        base64Body: ""`,
			want: "declares both body and base64Body",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			imp := &Importer{}
			_, err := imp.Import(context.Background(), ImportRequest{Content: manifestWithMock(tc.fields)})
			if err == nil || !errors.Is(err, ErrInvalidRequest) ||
				!strings.Contains(err.Error(), `action "mock-response"`) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Import returned %v, want the action id and %q", err, tc.want)
			}
		})
	}
}

func TestManifestPreservesExplicitEmptyMockBodies(t *testing.T) {
	cases := map[string]struct {
		fields     string
		body       bool
		base64Body bool
	}{
		"text":   {fields: `        body: ""`, body: true},
		"base64": {fields: `        base64Body: ""`, base64Body: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			module := parseFixture(t, manifestWithMock(tc.fields))
			mock := module.Scripts[0].Mock
			if (mock.Body != nil) != tc.body || (mock.Base64Body != nil) != tc.base64Body {
				t.Fatalf("body presence = %v, base64Body presence = %v", mock.Body != nil, mock.Base64Body != nil)
			}
			body, err := mock.bytes()
			if err != nil || len(body) != 0 {
				t.Fatalf("bytes = %v, %v; want an empty body", body, err)
			}
		})
	}
}

func TestManifestEnforcesDecodedMockBodyByteLimit(t *testing.T) {
	textAtLimit := strings.Repeat("x", maxMockBodyBytes)
	textAboveLimit := textAtLimit + "x"
	binaryAtLimit := bytes.Repeat([]byte{0xff}, maxMockBodyBytes)
	binaryAboveLimit := append(append([]byte(nil), binaryAtLimit...), 0xff)

	cases := map[string]struct {
		atLimit    string
		aboveLimit string
	}{
		"text": {
			atLimit:    "        body: '" + textAtLimit + "'",
			aboveLimit: "        body: '" + textAboveLimit + "'",
		},
		"base64": {
			atLimit:    "        base64Body: '" + base64.StdEncoding.EncodeToString(binaryAtLimit) + "'",
			aboveLimit: "        base64Body: '" + base64.StdEncoding.EncodeToString(binaryAboveLimit) + "'",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			parseFixture(t, manifestWithMock(tc.atLimit))

			imp := &Importer{}
			_, err := imp.Import(context.Background(), ImportRequest{Content: manifestWithMock(tc.aboveLimit)})
			if err == nil || !errors.Is(err, ErrInvalidRequest) ||
				!strings.Contains(err.Error(), `action "mock-response"`) ||
				!strings.Contains(err.Error(), fmt.Sprintf("exceeds %d bytes", maxMockBodyBytes)) {
				t.Fatalf("Import returned %v, want the action id and decoded byte limit", err)
			}
		})
	}
}

func TestExecuteMockReturnsDecodedBytes(t *testing.T) {
	want := []byte{0x00, 0x01, 0x02, 0xfe, 0xff}
	encoded := base64.StdEncoding.EncodeToString(want)
	result, err := executeMock(ScriptRule{Mock: &MockResponse{Base64Body: &encoded}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Body, want) {
		t.Fatalf("body = %v, want %v", result.Body, want)
	}
	if !result.Synthetic || !result.ChangedBody {
		t.Fatalf("result flags = %+v", result)
	}
}

func TestModuleBodyReservationsIncludeExactMockBodySize(t *testing.T) {
	largeBinary := bytes.Repeat([]byte{0xff}, maxMockBodyBytes)
	largeBase64 := base64.StdEncoding.EncodeToString(largeBinary)
	smallText := strings.Repeat("t", 2049)
	smallBinary := bytes.Repeat([]byte{0xa5}, 1537)
	smallBase64 := base64.StdEncoding.EncodeToString(smallBinary)

	cases := map[string]struct {
		mock *MockResponse
		want int64
	}{
		"one MiB base64": {
			mock: &MockResponse{Base64Body: &largeBase64},
			want: maxMockBodyBytes,
		},
		"small text is exact": {
			mock: &MockResponse{Body: &smallText},
			want: int64(len(smallText)),
		},
		"small padded base64 is exact": {
			mock: &MockResponse{Base64Body: &smallBase64},
			want: int64(len(smallBinary)),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := tc.mock.validate(); err != nil {
				t.Fatal(err)
			}
			if got := tc.mock.bodySize(); got != tc.want {
				t.Fatalf("validated body size = %d, want %d", got, tc.want)
			}
			rules := []matchedScriptRule{{Rule: ScriptRule{
				BodyMode:     "none",
				MaxBodyBytes: 1024,
				Mock:         tc.mock,
			}}}
			request := &M.Request{ContentLength: 0}
			if got := moduleBodyReservation(request, rules); got != tc.want {
				t.Fatalf("request reservation = %d, want %d", got, tc.want)
			}
			response := &M.Response{ContentLength: 1}
			responseWant := int64(1) + maxModuleHTTPBody + tc.want
			if got := moduleResponseBodyReservation(response, rules); got != responseWant {
				t.Fatalf("response reservation = %d, want %d", got, responseWant)
			}
			if allocations := testing.AllocsPerRun(100, func() {
				_ = moduleBodyReservation(request, rules)
				_ = moduleResponseBodyReservation(response, rules)
			}); allocations != 0 {
				t.Fatalf("reservation calculation allocated %.2f times per run", allocations)
			}
		})
	}
}

func TestModuleBodyBudgetRejectsConcurrentLargeMock(t *testing.T) {
	body := strings.Repeat("x", maxMockBodyBytes)
	mock := &MockResponse{Body: &body}
	if err := mock.validate(); err != nil {
		t.Fatal(err)
	}
	rules := []matchedScriptRule{{Rule: ScriptRule{
		BodyMode:     "none",
		MaxBodyBytes: 1024,
		Mock:         mock,
	}}}
	reservation := moduleBodyReservation(&M.Request{}, rules)
	if reservation < maxMockBodyBytes {
		t.Fatalf("reservation = %d, want at least %d", reservation, maxMockBodyBytes)
	}

	budget := newModuleBodyBudget(reservation)
	ctx := context.Background()
	if !budget.acquire(ctx, reservation, time.Second) {
		t.Fatal("first mock was not admitted")
	}
	second := make(chan bool, 1)
	go func() {
		second <- budget.acquire(ctx, reservation, 20*time.Millisecond)
	}()
	select {
	case admitted := <-second:
		if admitted {
			t.Fatal("a concurrent mock exceeded the resident body budget")
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent admission did not finish")
	}
	budget.release(reservation)
	if !budget.acquire(ctx, reservation, time.Second) {
		t.Fatal("reservation was not reusable after release")
	}
	budget.release(reservation)
}

func TestMockResponseJSONPersistenceKeepsStringFields(t *testing.T) {
	for _, document := range []string{
		`{"body":""}`,
		`{"base64_body":"AA=="}`,
	} {
		var mock MockResponse
		if err := json.Unmarshal([]byte(document), &mock); err != nil {
			t.Fatalf("Unmarshal(%s): %v", document, err)
		}
		roundTrip, err := json.Marshal(mock)
		if err != nil {
			t.Fatalf("Marshal(%s): %v", document, err)
		}
		if string(roundTrip) != document {
			t.Fatalf("round trip = %s, want %s", roundTrip, document)
		}
	}
}

type manifestParserFetch map[string]string

func (f manifestParserFetch) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	body, manifest := f[request.URL.String()]
	if !manifest {
		// The corpus gate owns only the manifest parser contract. A small valid
		// script lets Import traverse source-backed actions without reaching the
		// network; it does not verify or stand in for the published resource.
		body = "function transform(context) { return {}; }"
	}
	return &stdhttp.Response{
		StatusCode: stdhttp.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(stdhttp.Header),
		Request:    request,
	}, nil
}

func readManifestParserFixture(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, int64(maxManifestBytes)+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > maxManifestBytes {
		t.Fatalf("manifest fixture %s exceeds %d bytes", path, maxManifestBytes)
	}
	return string(body)
}

// TestOfficialExtensionManifestParserCorpus is an opt-in cross-repository
// parser gate. It sends every bounded manifest through Import while stubbing
// remote script bytes; it is not an extension installation or resource audit.
func TestOfficialExtensionManifestParserCorpus(t *testing.T) {
	root := strings.TrimSpace(os.Getenv("FIVEGPN_EXTENSIONS_ROOT"))
	if root == "" {
		t.Skip("FIVEGPN_EXTENSIONS_ROOT is not set")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(root, "*", "extension.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no official extension manifests found under %s", root)
	}

	served := make(manifestParserFetch)
	type fixture struct {
		path string
		url  string
	}
	fixtures := make([]fixture, 0, len(paths))
	for _, path := range paths {
		body := readManifestParserFixture(t, path)
		manifestURL := "https://official.example/" + filepath.Base(filepath.Dir(path)) + "/extension.yaml"
		served[manifestURL] = body
		fixtures = append(fixtures, fixture{path: path, url: manifestURL})
	}

	imp := &Importer{client: &stdhttp.Client{Transport: served}, now: time.Now}
	bilibiliImported := false
	for _, fixture := range fixtures {
		module, err := imp.Import(context.Background(), ImportRequest{URL: fixture.url})
		if err != nil {
			t.Errorf("import %s: %v", fixture.path, err)
			continue
		}
		if module.ID == "io.5gpn.bilibili-cleaner" {
			bilibiliImported = true
		}
	}
	if !bilibiliImported {
		t.Error("the official bilibili-cleaner manifest was not imported")
	}
}
