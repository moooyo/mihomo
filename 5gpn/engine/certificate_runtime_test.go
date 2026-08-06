package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/5gpn/state"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tls"
)

type runtimePlanResponseWriter struct {
	header http.Header
	status int
}

func (w *runtimePlanResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *runtimePlanResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(body), nil
}

func (w *runtimePlanResponseWriter) WriteHeader(status int) { w.status = status }

func publishTestCertificateResult(t *testing.T, e *Engine, status, code, message string) certificateRequest {
	t.Helper()
	cfg, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	request, err := readCertificateRequest(certificateRequestPath(e.config.path))
	if err != nil {
		t.Fatal(err)
	}
	result := certificateResult{
		Version: certificateStateVersion, TargetDigest: request.TargetDigest,
		Attempt: request.Attempt, Status: status, Code: code, Message: message,
	}
	if status == "ready" && len(request.Hosts) > 0 {
		certificateRaw, err := os.ReadFile(cfg.TLSCert)
		if err != nil {
			t.Fatal(err)
		}
		keyRaw, err := os.ReadFile(cfg.TLSKey)
		if err != nil {
			t.Fatal(err)
		}
		result.CertificateSHA256 = sha256Hex(certificateRaw)
		result.PrivateKeySHA256 = sha256Hex(keyRaw)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificateStatePath(cfg), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	e.certs.invalidateRuntimePlan()
	return request
}

func publishTestReadyCertificate(t *testing.T, e *Engine, serial int64) certificateRequest {
	t.Helper()
	cfg, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	request, err := readCertificateRequest(certificateRequestPath(e.config.path))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	writeTestLeafFor(t, cfg.TLSCert, cfg.TLSKey, serial, request.Hosts, now.Add(-time.Hour), now.Add(24*time.Hour))
	return publishTestCertificateResult(t, e, "ready", "", "")
}

func testClaimedMetadata(host string) *C.Metadata {
	return &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: host, DstPort: 443}
}

func TestCertificatePendingWithdrawsTheWholeRuntimePlan(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1

	state := e.CertificateRuntimeState()
	if state.Ready || state.Status != "pending" || state.TargetDigest == "" || state.Attempt == "" {
		t.Fatalf("certificate state = %+v, want identified pending request", state)
	}
	binding, exists := e.CaptureFor("shared.example.com")
	if !exists || binding.Ready {
		t.Fatalf("pending capture = %+v, %v", binding, exists)
	}
	if got := e.RouteClient(testClaimedMetadata("shared.example.com")); got != C.ClientRouteReject {
		t.Fatalf("pending claimed route = %v, want REJECT", got)
	}
	if got := e.RouteClient(testClaimedMetadata("unrelated.example.com")); got != C.ClientRouteNone {
		t.Fatalf("pending unrelated route = %v, want ordinary routing", got)
	}
	cfg, _ := e.config.Current()
	if hosts := e.readyCaptureHostPatterns(cfg); len(hosts) != 0 {
		t.Fatalf("pending ready hosts = %v", hosts)
	}
	module := e.ExtensionRuntimeState("first")
	if module.Ready || module.Phase != "certificate_pending" {
		t.Fatalf("pending module runtime = %+v", module)
	}
}

func TestClaimedHostCannotRacePendingPlanIntoOrdinaryRouting(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	publishTestReadyCertificate(t, e, 102)
	metadata := testClaimedMetadata("shared.example.com")
	if got := e.RouteClient(metadata); got != C.ClientRouteNone {
		t.Fatalf("ready pre-capture route = %v, want no fixed decision", got)
	}

	// This transition occurs between tunnel RouteClient and MatchTCP. MatchTCP
	// must claim the connection under the new pending generation rather than
	// decline it into the ordinary rule remainder evaluated from the old one.
	cfg := mustCurrentConfig(t, e)
	if err := os.Remove(certificateStatePath(cfg)); err != nil {
		t.Fatal(err)
	}
	e.certs.invalidateRuntimePlan()
	if binding, exists := e.CaptureFor(metadata.Host); !exists || binding.Ready || !binding.Claimed {
		t.Fatalf("pending binding = %+v, %v", binding, exists)
	}
	if !e.interceptor.MatchTCP(metadata) {
		t.Fatal("pending claimed host was declined into ordinary routing")
	}

	request, err := http.NewRequest(http.MethodGet, "http://shared.example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "shared.example.com"
	w := &runtimePlanResponseWriter{}
	e.proxy.ServeHTTP(w, request)
	if w.status != http.StatusServiceUnavailable {
		t.Fatalf("pending claimed HTTP status = %d, want 503", w.status)
	}
}

func TestCertificateCommitActivatesWithoutMovingConfigRevision(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	revision := e.Revision()
	publishTestReadyCertificate(t, e, 101)

	state := e.CertificateRuntimeState()
	if !state.Ready || state.Status != "ready" {
		t.Fatalf("certificate state = %+v", state)
	}
	if e.Revision() != revision {
		t.Fatalf("certificate commit moved revision from %s to %s", revision, e.Revision())
	}
	binding, exists := e.CaptureFor("shared.example.com")
	if !exists || !binding.Ready {
		t.Fatalf("ready capture = %+v, %v", binding, exists)
	}
	if got := e.RouteClient(testClaimedMetadata("shared.example.com")); got != C.ClientRouteNone {
		t.Fatalf("ready claimed route = %v, want capture path", got)
	}
	if runtime := e.ExtensionRuntimeState("first"); !runtime.Ready || runtime.Phase != "active" {
		t.Fatalf("ready module runtime = %+v", runtime)
	}
}

func TestCertificateRuntimeIsRebuiltAfterProcessRestart(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	request := publishTestReadyCertificate(t, e, 105)
	revision := e.Revision()

	reopened, err := New(e.config.path, filepath.Dir(e.config.path))
	if err != nil {
		t.Fatal(err)
	}
	reopened.certs.runtimeTTL = -1
	state := reopened.CertificateRuntimeState()
	if !state.Ready || state.Attempt != request.Attempt || reopened.Revision() != revision {
		t.Fatalf("reopened runtime=%+v revision=%s, want attempt=%s revision=%s", state, reopened.Revision(), request.Attempt, revision)
	}
}

func TestEmptyCertificateTargetCanBeReadyWithoutAKeypair(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultDocument()
	cfg.TLSCert = filepath.Join(dir, "tls", "fullchain.pem")
	cfg.TLSKey = filepath.Join(dir, "tls", "privkey.pem")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "intercept.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	e.certs.runtimeTTL = -1
	request := publishTestCertificateResult(t, e, "ready", "", "")
	if request.TargetDigest != digestText("\n") || len(request.Hosts) != 0 {
		t.Fatalf("empty request = %+v", request)
	}
	if state := e.CertificateRuntimeState(); !state.Ready || state.Status != "ready" {
		t.Fatalf("empty runtime = %+v", state)
	}
	if _, err := e.certs.GetCertificate(&tls.ClientHelloInfo{ServerName: "unclaimed.example"}); err == nil {
		t.Fatal("empty target served a certificate")
	}
}

func TestStaleCertificateResultsCannotReactivateAtoBtoC(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	requestA := publishTestReadyCertificate(t, e, 111)
	statePath := certificateStatePath(mustCurrentConfig(t, e))
	resultA, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.SetEgressGroup(e.Revision(), "second", "Proxies"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.SetEnabled(e.Revision(), "second", true); err != nil {
		t.Fatal(err)
	}
	requestB, err := readCertificateRequest(certificateRequestPath(e.config.path))
	if err != nil {
		t.Fatal(err)
	}
	if requestB.TargetDigest == requestA.TargetDigest || requestB.Attempt == requestA.Attempt {
		t.Fatal("B did not receive a distinct certificate identity")
	}
	if err := os.WriteFile(statePath, resultA, 0o640); err != nil {
		t.Fatal(err)
	}
	e.certs.invalidateRuntimePlan()
	if state := e.CertificateRuntimeState(); state.Ready || state.Status != "pending" {
		t.Fatalf("stale A result activated B: %+v", state)
	}

	if _, _, err := e.SetEnabled(e.Revision(), "second", false); err != nil {
		t.Fatal(err)
	}
	requestC, err := readCertificateRequest(certificateRequestPath(e.config.path))
	if err != nil {
		t.Fatal(err)
	}
	if requestC.TargetDigest != requestA.TargetDigest || requestC.Attempt == requestA.Attempt || requestC.Attempt == requestB.Attempt {
		t.Fatalf("C identity = %+v; want A target under a fresh attempt", requestC)
	}
	if state := e.CertificateRuntimeState(); state.Ready || state.Status != "pending" {
		t.Fatalf("stale A result activated C: %+v", state)
	}
	publishTestReadyCertificate(t, e, 113)
	if state := e.CertificateRuntimeState(); !state.Ready || state.Attempt != requestC.Attempt {
		t.Fatalf("current C result did not activate: %+v", state)
	}
}

func TestTornCertificatePairWithdrawsReadyRuntime(t *testing.T) {
	e, certPath, keyPath := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	publishTestReadyCertificate(t, e, 121)
	if !e.CertificateRuntimeState().Ready {
		t.Fatal("test pair did not become ready")
	}
	otherCert := filepath.Join(filepath.Dir(certPath), "other.pem")
	otherKey := filepath.Join(filepath.Dir(keyPath), "other-key.pem")
	writeTestLeaf(t, otherCert, otherKey)
	otherKeyRaw, err := os.ReadFile(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, otherKeyRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	state := e.CertificateRuntimeState()
	if state.Ready || state.Status != "error" || state.ErrorCode != "certificate_pair_torn" {
		t.Fatalf("torn pair state = %+v", state)
	}
	if binding, _ := e.CaptureFor("shared.example.com"); binding.Ready {
		t.Fatal("torn pair left capture ready")
	}
	if got := e.RouteClient(testClaimedMetadata("shared.example.com")); got != C.ClientRouteReject {
		t.Fatalf("torn pair route = %v, want REJECT", got)
	}
}

func TestCertificateRetryIsCASAndPendingIsIdempotent(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	request := publishTestCertificateResult(t, e, "error", "signing_failed", "The certificate could not be signed.")
	revision := e.Revision()

	if _, _, err := e.RetryCertificateRequest("stale", request.TargetDigest, request.Attempt); !errors.Is(err, state.ErrRevisionConflict) {
		t.Fatalf("stale revision retry = %v", err)
	}
	if _, _, err := e.RetryCertificateRequest(revision, request.TargetDigest, "00000000000000000000000000000000"); !errors.Is(err, ErrCertificateRetryConflict) {
		t.Fatalf("stale attempt retry = %v", err)
	}
	snapshot, returnedRevision, err := e.RetryCertificateRequest(revision, request.TargetDigest, request.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := readCertificateRequest(certificateRequestPath(e.config.path))
	if err != nil {
		t.Fatal(err)
	}
	if retried.Attempt == request.Attempt || retried.TargetDigest != request.TargetDigest || e.Revision() != revision {
		t.Fatalf("retry = %+v revision=%s", retried, e.Revision())
	}
	if returnedRevision != revision || snapshot.Certificate.Attempt != retried.Attempt || snapshot.Certificate.Status != "pending" {
		t.Fatalf("retry envelope revision=%s certificate=%+v", returnedRevision, snapshot.Certificate)
	}
	againSnapshot, againRevision, err := e.RetryCertificateRequest(revision, retried.TargetDigest, retried.Attempt)
	if err != nil || againRevision != revision || againSnapshot.Certificate.Attempt != retried.Attempt {
		t.Fatalf("pending retry = %+v, %s, %v", againSnapshot.Certificate, againRevision, err)
	}

	publishTestReadyCertificate(t, e, 131)
	if _, _, err := e.RetryCertificateRequest(revision, retried.TargetDigest, retried.Attempt); !errors.Is(err, ErrCertificateAlreadyReady) {
		t.Fatalf("ready retry = %v", err)
	}
}

func TestRuntimePlanCacheHasABoundedTTL(t *testing.T) {
	e, certPath, _ := newCertificateStateTestEngine(t)
	now := time.Now()
	e.certs.runtimeTTL = time.Second
	e.certs.runtimeNow = func() time.Time { return now }
	publishTestReadyCertificate(t, e, 141)
	if !e.CertificateRuntimeState().Ready {
		t.Fatal("test pair did not become ready")
	}
	if err := os.WriteFile(certPath, []byte("broken"), 0o640); err != nil {
		t.Fatal(err)
	}
	if !e.CertificateRuntimeState().Ready {
		t.Fatal("hot runtime plan did not honor its bounded TTL")
	}
	now = now.Add(time.Second + time.Nanosecond)
	if state := e.CertificateRuntimeState(); state.Ready || state.ErrorCode != "certificate_pair_torn" {
		t.Fatalf("expired runtime cache retained a changed pair: %+v", state)
	}
}

func TestGetConfigForClientFencesSNIAndTicketGenerations(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	publishTestReadyCertificate(t, e, 151)
	config, err := e.proxy.mitmTLSConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	if config.GetConfigForClient == nil {
		t.Fatal("MITM TLS config has no ClientHello plan gate")
	}
	selected, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "shared.example.com"})
	if err != nil || len(selected.Certificates) != 1 {
		t.Fatalf("selected TLS config = %+v, %v", selected, err)
	}
	firstGeneration := e.proxy.tlsPlan
	firstKeys := append([][32]byte(nil), e.proxy.tlsKeys...)
	if firstGeneration == "" || len(firstKeys) == 0 {
		t.Fatal("first plan did not establish ticket keys")
	}
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "unrelated.example.com"}); err == nil {
		t.Fatal("unclaimed SNI received a TLS config")
	}

	request := publishTestCertificateResult(t, e, "error", "renewal_failed", "The certificate renewal failed.")
	_, _, err = e.RetryCertificateRequest(e.Revision(), request.TargetDigest, request.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := readCertificateRequest(certificateRequestPath(e.config.path))
	if err != nil {
		t.Fatal(err)
	}
	publishTestReadyCertificate(t, e, 152)
	if retried.Attempt == request.Attempt {
		t.Fatal("retry did not move the plan attempt")
	}
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "shared.example.com"}); err != nil {
		t.Fatal(err)
	}
	if e.proxy.tlsPlan == firstGeneration || len(e.proxy.tlsKeys) == 0 || e.proxy.tlsKeys[0] == firstKeys[0] {
		t.Fatal("new certificate plan retained an old ticket generation")
	}
}

func TestTLSResumptionCannotCrossCertificatePlanGeneration(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	publishTestReadyCertificate(t, e, 155)
	clientConfig := &tls.Config{
		ServerName:         "shared.example.com",
		InsecureSkipVerify: true, // The test leaf is intentionally self-signed.
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}
	handshake := func() tls.ConnectionState {
		t.Helper()
		serverSide, clientSide := net.Pipe()
		deadline := time.Now().Add(5 * time.Second)
		_ = serverSide.SetDeadline(deadline)
		_ = clientSide.SetDeadline(deadline)
		serverConfig, err := e.proxy.mitmTLSConfigForConnection(true, &tlsConnectionPlan{})
		if err != nil {
			t.Fatal(err)
		}
		serverDone := make(chan error, 1)
		go func() {
			server := tls.Server(serverSide, serverConfig)
			serverDone <- server.Handshake()
			_ = serverSide.Close()
		}()
		client := tls.Client(clientSide, clientConfig)
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		connectionState := client.ConnectionState()
		_ = clientSide.Close()
		if err := <-serverDone; err != nil {
			t.Fatal(err)
		}
		return connectionState
	}

	if state := handshake(); state.DidResume {
		t.Fatal("first TLS connection unexpectedly resumed")
	}
	if state := handshake(); !state.DidResume {
		t.Fatal("second TLS connection did not resume within one certificate plan")
	}
	request := publishTestCertificateResult(t, e, "error", "renewal_failed", "The certificate renewal failed.")
	if _, _, err := e.RetryCertificateRequest(e.Revision(), request.TargetDigest, request.Attempt); err != nil {
		t.Fatal(err)
	}
	publishTestReadyCertificate(t, e, 156)
	if state := handshake(); state.DidResume {
		t.Fatal("TLS session resumed across certificate plan generations")
	}
}

func TestEstablishedHTTP2ConnectionCannotCrossCertificatePlanGeneration(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	publishTestReadyCertificate(t, e, 161)
	connectionPlan := &tlsConnectionPlan{}
	config, err := e.proxy.mitmTLSConfigForConnection(true, connectionPlan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "shared.example.com"}); err != nil {
		t.Fatal(err)
	}
	oldGeneration := connectionPlan.current()

	request := publishTestCertificateResult(t, e, "error", "renewal_failed", "The certificate renewal failed.")
	if _, _, err := e.RetryCertificateRequest(e.Revision(), request.TargetDigest, request.Attempt); err != nil {
		t.Fatal(err)
	}
	publishTestReadyCertificate(t, e, 162)
	if current := e.certs.runtimePlan(mustCurrentConfig(t, e)).generation; current == "" || current == oldGeneration {
		t.Fatal("test did not move the certificate plan generation")
	}

	ctx := context.WithValue(context.Background(), tlsConnectionPlanContextKey{}, connectionPlan)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://shared.example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest.Host = "shared.example.com"
	httpRequest.Proto = "HTTP/2.0"
	httpRequest.ProtoMajor = 2
	w := &runtimePlanResponseWriter{}
	e.proxy.ServeHTTP(w, httpRequest)
	if w.status != http.StatusMisdirectedRequest {
		t.Fatalf("old HTTP/2 connection status = %d, want 421", w.status)
	}
}

func installSyntheticRuntimeAction(t *testing.T, e *Engine) {
	t.Helper()
	body := "synthetic action executed"
	_, _, err := e.config.Update(e.Revision(), func(current Config) (Config, error) {
		candidate := cloneConfig(current)
		module, err := findModule(&candidate, "first")
		if err != nil {
			return current, err
		}
		module.Scripts = append(module.Scripts, ScriptRule{
			ID: "runtime-gate-proof", Phase: "request",
			Match: ActionMatch{
				Hosts: []string{"shared.example.com"}, Schemes: []string{"https"}, PathRegex: ".*",
			},
			Mock:     &MockResponse{Status: 299, Body: &body},
			BodyMode: "none", TimeoutMS: 500, MaxBodyBytes: 1024,
		})
		return candidate, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func currentH2ConnectionPlan(t *testing.T, e *Engine) *tlsConnectionPlan {
	t.Helper()
	connectionPlan := &tlsConnectionPlan{}
	config, err := e.proxy.mitmTLSConfigForConnection(true, connectionPlan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "shared.example.com"}); err != nil {
		t.Fatal(err)
	}
	return connectionPlan
}

func serveSyntheticH2(t *testing.T, e *Engine, connectionPlan *tlsConnectionPlan) int {
	t.Helper()
	ctx := context.WithValue(context.Background(), tlsConnectionPlanContextKey{}, connectionPlan)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://shared.example.com/proof", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "shared.example.com"
	request.Proto = "HTTP/2.0"
	request.ProtoMajor = 2
	request.TLS = &tls.ConnectionState{ServerName: "shared.example.com"}
	w := &runtimePlanResponseWriter{}
	e.proxy.ServeHTTP(w, request)
	return w.status
}

func TestExistingH2SyntheticActionStopsWhenBoundaryIsWithdrawn(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	publishTestReadyCertificate(t, e, 171)
	installSyntheticRuntimeAction(t, e)
	boundaryReady := true
	e.SetClientBoundarySource(func() bool { return boundaryReady })
	connectionPlan := currentH2ConnectionPlan(t, e)
	if status := serveSyntheticH2(t, e, connectionPlan); status != 299 {
		t.Fatalf("ready synthetic status = %d, want 299", status)
	}

	boundaryReady = false
	if status := serveSyntheticH2(t, e, connectionPlan); status != http.StatusServiceUnavailable {
		t.Fatalf("withdrawn-boundary synthetic status = %d, want 503", status)
	}
}

func TestExistingH2SyntheticActionStopsWhenWinningEgressIsWithdrawn(t *testing.T) {
	e, _, _ := newCertificateStateTestEngine(t)
	e.certs.runtimeTTL = -1
	publishTestReadyCertificate(t, e, 172)
	installSyntheticRuntimeAction(t, e)
	egressReady := true
	e.SetEgressGroupSource(func(name string) bool { return name == "GroupA" && egressReady }, nil)
	if _, _, err := e.SetEgressGroup(e.Revision(), "first", "GroupA"); err != nil {
		t.Fatal(err)
	}
	connectionPlan := currentH2ConnectionPlan(t, e)
	if status := serveSyntheticH2(t, e, connectionPlan); status != 299 {
		t.Fatalf("ready synthetic status = %d, want 299", status)
	}

	egressReady = false
	if status := serveSyntheticH2(t, e, connectionPlan); status != http.StatusServiceUnavailable {
		t.Fatalf("withdrawn-egress synthetic status = %d, want 503", status)
	}
}

func mustCurrentConfig(t *testing.T, e *Engine) Config {
	t.Helper()
	cfg, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
