package engine

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tls"
)

type interceptProxy struct {
	config        *configStore
	certificates  *certificateStore
	upstreamRoots *x509.CertPool
	scripts       *scriptRuntime
	tlsErrors     *tlsHandshakeErrorReporter
	// logs is set by setEngineLogPublisher alongside scripts.logs and
	// tlsErrors.logs. A proxy assembled field by field in a test has to set it
	// too, or its capacity and transformation reports go nowhere.
	logs       engineLogPublisher
	bodyBudget *moduleBodyBudget
	fatal      func(error)
	// runtimeReady is installed once during Engine assembly. It revalidates the
	// current host against the complete certificate, fixed-boundary and winning
	// egress plan before any request body or action is observed.
	runtimeReady func(Config, string) bool

	transportMu sync.Mutex
	upstream    *upstreamTransportGeneration

	// The client-facing TLS leg's shared session ticket keys. Every connection
	// clones a config from these rather than building its own, which is what
	// makes resumption possible at all; see mitmTLSConfig.
	tlsMu      sync.Mutex
	tlsKeys    [][32]byte
	tlsKeysSet time.Time
	tlsPlan    string
	tlsNow     func() time.Time
}

type tlsConnectionPlan struct {
	generation atomic.Pointer[string]
}

type tlsConnectionPlanContextKey struct{}

func (p *tlsConnectionPlan) set(generation string) {
	value := generation
	p.generation.Store(&value)
}

func (p *tlsConnectionPlan) current() string {
	if p == nil {
		return ""
	}
	if value := p.generation.Load(); value != nil {
		return *value
	}
	return ""
}

const (
	// How long one client-facing session ticket key issues tickets for, and how
	// many are kept so a ticket issued just before a rotation still resumes.
	// This is what crypto/tls does for a server that manages its own keys; the
	// keys are set explicitly here only because a per-connection clone cannot
	// inherit ones the template never generated.
	mitmTicketKeyLifetime = 24 * time.Hour
	mitmTicketKeyHistory  = 2
)

const (
	maxIdleUpstreamHTTPConnections        = 64
	maxIdleUpstreamHTTPConnectionsPerHost = 8
	upstreamHTTPIdleTimeout               = 90 * time.Second
	// The in-process inner dial and the subsequent TLS handshake each use this
	// ceiling, matching net/http's own DefaultTransport.
	upstreamHandshakeTimeout = 10 * time.Second
	// Time to first byte only: ResponseHeaderTimeout starts after the request
	// body has been written, so a slow upload never starts this clock. 90s is the
	// silence budget this file already spends three times, and it sits above the
	// common origin-side ceilings a proxy meets.
	upstreamResponseHeaderTimeout = 90 * time.Second
	// The data plane's silence budget for a peer that goes quiet inside a request
	// rather than between them, which is the same 90s the three idle timeouts
	// above already spend. Re-armed per read and per write, so a slow but
	// progressing transfer is never truncated.
	interceptTransferStallTimeout = 90 * time.Second
	interceptTransferWriteChunk   = 32 << 10
	// Bound the number of handler goroutines and request/response projections one
	// client connection can create. Process-wide action and body admission still
	// apply across connections; this closes the HTTP/2 per-connection multiplier
	// before those global limits are reached.
	maxInterceptHTTP2Streams = 32
	// A reservation is held until its request finishes, so a saturated pool does
	// not clear inside this window. What the wait buys is the burst that clears in
	// milliseconds; waiting longer would only pin this request's connection, and
	// its upstream one, behind a shortage it cannot outlast.
	moduleBodySlotWait = 250 * time.Millisecond

	// Enough that a burst across a handful of origins keeps resuming, small
	// enough that a retired generation's cache is trivial to drop.
	upstreamSessionCacheEntries = 64

	interceptCertificateTrustLogInterval = time.Minute
	interceptCertificateTrustMessage     = "client rejected the interception certificate as untrusted; open Setup Guide, install the current 5gpn interception CA, and enable full trust on the client"
)

type upstreamTransportGeneration struct {
	generation uint64
	projection upstreamTransportProjection

	mu             sync.Mutex
	httpTransports map[string]*http.Transport
	closed         bool
	closeOnce      sync.Once

	// refs and retired are protected by interceptProxy.transportMu.
	refs    int
	retired bool
}

type tlsHandshakeErrorReporter struct {
	mu               sync.Mutex
	lastTrustWarning time.Time
	now              func() time.Time
	logs             engineLogPublisher
	logger           *log.Logger
}

type tlsHandshakeErrorWriter struct {
	reporter *tlsHandshakeErrorReporter
	target   string
}

func newTLSHandshakeErrorReporter() *tlsHandshakeErrorReporter {
	return &tlsHandshakeErrorReporter{now: time.Now, logger: log.Default()}
}

func (r *tlsHandshakeErrorReporter) writer(target string) io.Writer {
	return &tlsHandshakeErrorWriter{reporter: r, target: target}
}

func (w *tlsHandshakeErrorWriter) Write(payload []byte) (int, error) {
	if w != nil && w.reporter != nil {
		w.reporter.report(w.target, strings.TrimSpace(string(payload)))
	}
	return len(payload), nil
}

func (r *tlsHandshakeErrorReporter) report(target, message string) {
	if r == nil || message == "" {
		return
	}
	logger := r.logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("intercept: target=%q %s", target, message)
	if !strings.Contains(strings.ToLower(message), "remote error: tls: unknown certificate") {
		return
	}
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	r.mu.Lock()
	if !r.lastTrustWarning.IsZero() && now.Before(r.lastTrustWarning.Add(interceptCertificateTrustLogInterval)) {
		r.mu.Unlock()
		return
	}
	r.lastTrustWarning = now
	r.mu.Unlock()

	logger.Printf("intercept: target=%q %s", target, interceptCertificateTrustMessage)
	if engineLogPublishingEnabled(r.logs) {
		r.logs.Publish(EngineLog{
			Level: "warn", Source: "engine", URL: "https://" + target,
			Message: interceptCertificateTrustMessage,
		})
	}
}

// interceptStoreFile is the fixed name of the extensions' persistent store
// inside the engine state directory. Keeping it relative to stateDir ensures
// the selected state directory owns the complete storage path.
const interceptStoreFile = "store.json"

func newInterceptProxy(config *configStore, certificates *certificateStore, workers *workerController, stateDir string) *interceptProxy {
	scripts := newScriptRuntimeWithWorker(workers, nil, filepath.Join(stateDir, interceptStoreFile))
	return &interceptProxy{
		config: config, certificates: certificates, scripts: scripts, tlsErrors: newTLSHandshakeErrorReporter(),
		bodyBudget: newModuleBodyBudget(maxModuleBodyBudgetBytes),
	}
}

func (p *interceptProxy) setEngineLogPublisher(logs engineLogPublisher) {
	p.logs = logs
	p.scripts.logs = logs
	p.tlsErrors.logs = logs
}

func (p *interceptProxy) servePlainHTTPConnection(conn net.Conn) error {
	listener := newSingleConnListener(conn)
	server := &http.Server{
		Handler:           p.failFastHandler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: maxInterceptHTTP2Streams},
	}
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (p *interceptProxy) serveTLSConnection(conn net.Conn, target string) error {
	cfg, err := p.config.Current()
	if err != nil {
		return err
	}
	connectionPlan := &tlsConnectionPlan{}
	tlsConfig, err := p.mitmTLSConfigForConnection(cfg.MITM.HTTP2, connectionPlan)
	if err != nil {
		return err
	}
	listener := newSingleConnListener(conn)
	server := &http.Server{
		Handler:           p.failFastHandler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(p.tlsErrors.writer(target), "", 0),
		TLSConfig:         tlsConfig,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: maxInterceptHTTP2Streams},
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, tlsConnectionPlanContextKey{}, connectionPlan)
		},
	}
	err = server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type failFastInterceptHandler struct {
	next  http.Handler
	fatal func(error)
}

const (
	interceptAltSvcHeader = "Alt-Svc"
	interceptAltSvcClear  = "clear"
)

// pinInterceptAltSvc owns Alt-Svc at the downstream boundary. The handler sets
// it before any error path can write, and both successful response writers set
// it again after origin and extension headers have reached their final form.
func pinInterceptAltSvc(header http.Header) {
	for name := range header {
		if strings.EqualFold(name, interceptAltSvcHeader) {
			delete(header, name)
		}
	}
	header.Set(interceptAltSvcHeader, interceptAltSvcClear)
}

func (p *interceptProxy) failFastHandler() http.Handler {
	return failFastInterceptHandler{next: p, fatal: p.fatal}
}

func (h failFastInterceptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pinInterceptAltSvc(w.Header())
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		if recovered == http.ErrAbortHandler {
			panic(recovered)
		}
		failure := fmt.Errorf("5gpn/engine: unexpected HTTP handler panic: %v", recovered)
		if h.fatal != nil {
			h.fatal(failure)
		}
		// The production fatal handler terminates the process. Re-panic if an
		// injected test handler returns so net/http still aborts this request.
		panic(recovered)
	}()
	h.next.ServeHTTP(w, r)
}

// mitmTLSConfig builds this connection's client-facing TLS config from keys the
// whole process shares.
//
// Every connection used to construct its own tls.Config, and a server's session
// ticket keys belong to its config: a ticket issued on one connection could
// never be decrypted on the next, so the MITM leg never resumed and every
// connection paid a full handshake and a signature. Measured against this
// certificate: a fresh config per connection resumes on no connection, a clone
// of a template whose keys were never set resumes on none either, and a clone of
// one carrying explicit keys resumes from the second connection on, under both
// TLS 1.2 and TLS 1.3.
//
// The clone is not incidental. http.Server.ServeTLS hands its TLSConfig to
// http2ConfigureServer, which writes to it, and this proxy builds one
// http.Server per connection -- so a config shared by pointer would be written
// by every connection at once. Each connection gets its own object and only the
// keys are shared.
//
// NextProtos comes from the caller's snapshot rather than the template because
// MITM.HTTP2 can change under a running process.
func (p *interceptProxy) mitmTLSConfig(http2 bool) (*tls.Config, error) {
	return p.mitmTLSConfigForConnection(http2, nil)
}

func (p *interceptProxy) mitmTLSConfigForConnection(http2 bool, connectionPlan *tlsConnectionPlan) (*tls.Config, error) {
	if p == nil || p.certificates == nil {
		return nil, errors.New("interception certificate source is unavailable")
	}
	config := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: p.certificates.GetCertificate,
		NextProtos:     mitmTLSNextProtos(http2),
	}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		certificate, generation, err := p.certificates.certificateForHello(hello)
		if err != nil {
			return nil, err
		}
		if connectionPlan != nil {
			connectionPlan.set(generation)
		}
		keys, err := p.sessionTicketKeys(generation)
		if err != nil {
			return nil, err
		}
		selected := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*certificate},
			NextProtos:   mitmTLSNextProtos(http2),
		}
		selected.SetSessionTicketKeys(keys)
		return selected, nil
	}
	return config, nil
}

// sessionTicketKeys returns the keys to issue and accept tickets under, newest
// first, rotating them on the same daily schedule crypto/tls uses for a server
// that manages its own. The previous key is kept so a ticket issued just before
// a rotation still resumes rather than silently falling back to a full
// handshake.
func (p *interceptProxy) sessionTicketKeys(planGeneration string) ([][32]byte, error) {
	if planGeneration == "" {
		return nil, errors.New("session ticket key requires a certificate plan generation")
	}
	now := time.Now
	if p.tlsNow != nil {
		now = p.tlsNow
	}
	p.tlsMu.Lock()
	defer p.tlsMu.Unlock()
	if p.tlsPlan != planGeneration {
		// Never retain a decryption key across certificate-plan generations. A
		// resumed handshake does not select a certificate, so accepting an old
		// ticket would otherwise bypass the new host-set and leaf boundary.
		p.tlsPlan = planGeneration
		p.tlsKeys = nil
		p.tlsKeysSet = time.Time{}
	}
	if len(p.tlsKeys) > 0 && now().Sub(p.tlsKeysSet) < mitmTicketKeyLifetime {
		return append([][32]byte(nil), p.tlsKeys...), nil
	}
	var fresh [32]byte
	if _, err := rand.Read(fresh[:]); err != nil {
		return nil, fmt.Errorf("session ticket key: %w", err)
	}
	rotated := append([][32]byte{fresh}, p.tlsKeys...)
	if len(rotated) > mitmTicketKeyHistory {
		rotated = rotated[:mitmTicketKeyHistory]
	}
	p.tlsKeys = rotated
	p.tlsKeysSet = now()
	return append([][32]byte(nil), rotated...), nil
}

func mitmTLSNextProtos(http2 bool) []string {
	if http2 {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func (p *interceptProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := canonicalHost(r.Host)
	cfg, err := p.config.Current()
	if err != nil {
		http.Error(w, "interception configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	if !activeInterceptHost(cfg, host) {
		http.Error(w, "unrecognized interception host", http.StatusMisdirectedRequest)
		return
	}
	if p.certificates != nil {
		plan := p.certificates.runtimePlan(cfg)
		if !plan.state.Ready || plan.certificate == nil {
			http.Error(w, "interception certificate plan unavailable", http.StatusServiceUnavailable)
			return
		}
		if connectionPlan, ok := r.Context().Value(tlsConnectionPlanContextKey{}).(*tlsConnectionPlan); ok {
			generation := connectionPlan.current()
			if generation == "" || generation != plan.generation {
				http.Error(w, "interception connection plan changed", http.StatusMisdirectedRequest)
				return
			}
			if err := plan.certificate.Leaf.VerifyHostname(host); err != nil {
				http.Error(w, "interception certificate does not cover the request host", http.StatusMisdirectedRequest)
				return
			}
		}
	}
	if p.runtimeReady != nil && !p.runtimeReady(cfg, host) {
		http.Error(w, "interception runtime plan unavailable", http.StatusServiceUnavailable)
		return
	}
	if requestHasPayload(r) {
		controller := http.NewResponseController(w)
		// Armed before the first read as well: when this handler answers without
		// draining the body, net/http drains up to maxPostHandlerReadBytes of it
		// outside the wrapper, and the synthetic-response path relies on that.
		_ = controller.SetReadDeadline(time.Now().Add(interceptTransferStallTimeout))
		serverBody := r.Body
		r.Body = &transferDeadlineBody{ReadCloser: serverBody, controller: controller, timeout: interceptTransferStallTimeout}
		// Handed back so net/http still recognises its own body type after the
		// handler returns: chunkWriter.writeHeader only skips draining an already
		// rejected oversize upload when Request.Body is the concrete type it
		// created, and that is what keeps those bytes off the wire.
		defer func() { r.Body = serverBody }()
	}
	requestProbe := moduleRequestProbe(r, host)
	requestRules := matchingScriptRules(cfg, "request", requestProbe)
	bodySlotHeld := requestNeedsModuleBodyReservation(r, requestRules)
	bodyReserved := moduleBodyReservation(r, requestRules)
	if bodySlotHeld && !p.acquireBodySlot(r.Context(), bodyReserved) {
		p.reportModuleBodyCapacityBusy(r, host, "request", requestProbe)
		http.Error(w, "interception body capacity is busy", http.StatusServiceUnavailable)
		return
	}
	defer func() {
		if bodySlotHeld {
			p.releaseBodySlot(bodyReserved)
		}
	}()
	prepared, prepareErr := p.prepareModuleRequestWithRules(w, r, cfg, requestProbe, requestRules)
	if bodySlotHeld && !prepared.bodyBufferRetained {
		p.releaseBodySlot(bodyReserved)
		bodySlotHeld = false
	} else if bodySlotHeld && prepared.bodyBufferBytes < bodyReserved {
		// The reservation was taken before the length was known, so an
		// undeclared-length request reserved everything it was allowed to read.
		// Now the buffer exists: hold what it actually costs for the round trip
		// rather than the worst case it might have been.
		p.releaseBodySlot(bodyReserved - prepared.bodyBufferBytes)
		bodyReserved = prepared.bodyBufferBytes
	}
	if prepared.handled {
		return
	}
	if prepareErr != nil {
		p.reportTransformFailure("request", requestProbe.URL, prepareErr)
		log.Printf("intercept: request transformation failed host=%s protocol=%s", host, r.Proto)
		http.Error(w, "interception request transformation failed", http.StatusBadGateway)
		return
	}

	outbound := prepared.outbound
	response, cleanup, err := p.roundTrip(outbound, cfg, prepared.egressOwner)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		log.Printf("intercept: upstream request failed host=%s protocol=%s: %v", host, r.Proto, err)
		http.Error(w, "interception upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseProbe := scriptMessage{
		URL: outbound.URL.String(), Method: outbound.Method, StatusCode: response.StatusCode,
	}
	// Filtered from the probe taken while the outbound headers were built, which
	// is a superset of this match: the status code was the only thing it could
	// not evaluate. Walking every rule again would also re-parse the URL.
	responseRules := responseRulesForStatus(prepared.responseCandidates, response.StatusCode)
	// A rule set that never reads the body streams. See responseRulesStreamable:
	// the buffered path holds the whole response in memory -- up to the global
	// 64 MiB, because moduleBodyReadLimit skips "none" mode rules -- so one
	// header edit scoped `^/` used to buffer every download on that host, delay
	// its first byte until the origin finished, hold a process body slot
	// throughout, and 502 above the cap on an exchange that had succeeded.
	if responseRulesStreamable(responseRules) {
		if err := p.applyStreamingResponseHeaderEdits(outbound, response, cfg, responseRules); err != nil {
			p.reportTransformFailure("response", responseProbe.URL, err)
			log.Printf("intercept: response header edit failed host=%s protocol=%s", host, r.Proto)
			http.Error(w, "interception response transformation failed", http.StatusBadGateway)
			return
		}
		if copyErr := writeStreamingProxyResponse(w, r.ProtoMajor, r.Method, response); copyErr != nil {
			log.Printf("intercept: upstream response copy failed host=%s protocol=%s: %v", host, r.Proto, copyErr)
			panic(http.ErrAbortHandler)
		}
		return
	}
	if len(responseRules) > 0 {
		// The upstream leg has already run, so a capacity rejection here cannot be
		// an "unavailable, try again": the request was made. This is the same
		// condition as any other unrunnable response action and takes the same
		// fail-closed exit rather than passing the raw response through.
		//
		// Reserved separately from the request leg rather than reusing whatever
		// that leg happened to leave held: when the request buffer was retained
		// both bodies are resident at once, and the previous form skipped the
		// response reservation entirely in exactly that case. What is reserved is
		// what transformModuleResponse will actually read, which is not the widest
		// declared limit -- see moduleResponseBodyReservation.
		responseReserved := moduleResponseBodyReservation(response, responseRules)
		if !p.acquireBodySlot(r.Context(), responseReserved) {
			p.reportModuleBodyCapacityBusy(r, host, "response", responseProbe)
			http.Error(w, "interception response transformation failed", http.StatusBadGateway)
			return
		}
		defer p.releaseBodySlot(responseReserved)
	}

	transformed, transformErr := p.transformModuleResponse(outbound, response, cfg, responseRules)
	if transformErr != nil {
		p.reportTransformFailure("response", responseProbe.URL, transformErr)
		log.Printf("intercept: response transformation failed host=%s protocol=%s", host, r.Proto)
		http.Error(w, "interception response transformation failed", http.StatusBadGateway)
		return
	}
	if transformed != nil {
		if writeErr := writeBufferedModuleResponse(w, r.Method, transformed.StatusCode, transformed.Header, transformed.Trailer, transformed.Body); writeErr != nil {
			log.Printf("intercept: transformed response write failed host=%s protocol=%s: %v", host, r.Proto, writeErr)
			panic(http.ErrAbortHandler)
		}
		return
	}

	if copyErr := writeStreamingProxyResponse(w, r.ProtoMajor, r.Method, response); copyErr != nil {
		log.Printf("intercept: upstream response copy failed host=%s protocol=%s: %v", host, r.Proto, copyErr)
		panic(http.ErrAbortHandler)
	}
}

// transferDeadlineBody and transferDeadlineWriter re-arm the stall deadline for
// every I/O operation. MaxBytesReader bounds bytes, not time, while a flat
// request deadline would truncate a large transfer that continues to make
// progress. Per-operation deadlines stop a peer that stalls without penalizing
// a slow but active transfer.
type transferDeadlineBody struct {
	io.ReadCloser
	controller *http.ResponseController
	timeout    time.Duration
}

func (b *transferDeadlineBody) Read(buffer []byte) (int, error) {
	_ = b.controller.SetReadDeadline(time.Now().Add(b.timeout))
	return b.ReadCloser.Read(buffer)
}

type transferDeadlineWriter struct {
	io.Writer
	controller *http.ResponseController
	timeout    time.Duration
}

// A Write must place every byte it is given, so unlike a Read it can outlive any
// single window: writeBufferedModuleResponse hands over a whole body at once, and
// io.Copy collapses to a single Write whenever the source implements WriterTo.
// Re-arm per chunk, the unit io.Copy already moves.
func (w *transferDeadlineWriter) Write(payload []byte) (int, error) {
	written := 0
	for written < len(payload) {
		chunk := payload[written:]
		if len(chunk) > interceptTransferWriteChunk {
			chunk = chunk[:interceptTransferWriteChunk]
		}
		_ = w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
		count, err := w.Writer.Write(chunk)
		written += count
		if err != nil {
			return written, err
		}
		if count < len(chunk) {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (p *interceptProxy) acquireBodySlot(ctx context.Context, bytes int64) bool {
	if p.bodyBudget == nil {
		return true
	}
	return p.bodyBudget.acquire(ctx, bytes, moduleBodySlotWait)
}

// A capacity rejection is the one handler exit that is not a fault, which is what
// makes it easy to lose: report it on the operator log like every other exit, and
// on the engine log stream the console reads, so an extension that stopped
// running is visible as something other than silence.
func (p *interceptProxy) reportModuleBodyCapacityBusy(r *http.Request, host, phase string, probe scriptMessage) {
	log.Printf("intercept: module body capacity is busy host=%s protocol=%s phase=%s", host, r.Proto, phase)
	if !engineLogPublishingEnabled(p.logs) {
		return
	}
	p.logs.Publish(EngineLog{
		Level: "warn", Source: "engine", Phase: phase, URL: sanitizeEngineLogURL(probe.URL),
		Message: "interception body capacity is busy; the matched extension action did not run",
	})
}

// A transformation error can quote a script's own exception text and the URL a
// script asked to rewrite to, so the cause goes to the engine log, where
// truncateEngineLogField bounds the message, and never to journald.
func (p *interceptProxy) reportTransformFailure(phase, requestURL string, err error) {
	if !engineLogPublishingEnabled(p.logs) {
		return
	}
	p.logs.Publish(EngineLog{
		Level: "error", Source: "engine", Phase: phase, URL: sanitizeEngineLogURL(requestURL),
		Message: phase + " transformation failed: " + err.Error(),
	})
}

func (p *interceptProxy) releaseBodySlot(bytes int64) {
	if p.bodyBudget != nil {
		p.bodyBudget.release(bytes)
	}
}

func requestHasPayload(request *http.Request) bool {
	return request != nil && request.Body != nil && (request.ContentLength != 0 || len(request.TransferEncoding) > 0)
}

func requestHasBodySection(request *http.Request) bool {
	if request == nil {
		return false
	}
	return requestHasPayload(request) || len(request.Trailer) > 0
}

func (p *interceptProxy) roundTrip(request *http.Request, cfg Config, owner string) (*http.Response, func(), error) {
	generation, cleanup := p.acquireUpstreamTransportGeneration(cfg)
	if err := authorizeProjectedRequest(request, generation.projection, owner); err != nil {
		return nil, cleanup, err
	}
	transport, err := generation.getHTTPTransport(p, owner)
	if err != nil {
		return nil, cleanup, err
	}
	response, err := transport.RoundTrip(request)
	return response, cleanup, err
}

func authorizeProjectedRequest(request *http.Request, projection upstreamTransportProjection, owner string) error {
	if request == nil || request.URL == nil {
		return errors.New("upstream request target is missing")
	}
	port := request.URL.Port()
	if port == "" {
		if request.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	target, permitted := projection.targets.upstreamTarget(request.URL.Hostname(), port, owner)
	if !permitted {
		return errors.New("upstream target is outside the active extension allowlist")
	}
	_, err := authorizeUpstream(C.TCP, target)
	return err
}

func newUpstreamTransportGeneration(cfg Config) *upstreamTransportGeneration {
	projection := newUpstreamTransportProjection(cfg)
	return &upstreamTransportGeneration{
		generation:     projection.generation,
		projection:     projection,
		httpTransports: make(map[string]*http.Transport),
	}
}

func (p *interceptProxy) acquireUpstreamTransportGeneration(cfg Config) (*upstreamTransportGeneration, func()) {
	var closeIdle *upstreamTransportGeneration
	var closeNow *upstreamTransportGeneration

	p.transportMu.Lock()
	generation := p.upstream
	switch {
	case cfg.generation == 0:
		generation = newUpstreamTransportGeneration(cfg)
		generation.retired = true
	case generation == nil || cfg.generation > generation.generation:
		// A newer document is not by itself a reason to drop warm connections.
		// The generation number advances on any content change, and almost none
		// of them reach the upstream leg -- a setting, an enable toggle, a
		// script body, a match pattern all leave the proxy, the protocol and the
		// target authorization untouched. Only when the fingerprint moves has
		// this pool stopped being authorized for what it holds.
		if generation != nil && newUpstreamTransportProjection(cfg).fingerprint == generation.projection.fingerprint {
			generation.generation = cfg.generation
			break
		}
		previous := generation
		generation = newUpstreamTransportGeneration(cfg)
		p.upstream = generation
		if previous != nil {
			previous.retired = true
			if previous.refs == 0 {
				closeNow = previous
			} else {
				closeIdle = previous
			}
		}
	case cfg.generation < generation.generation:
		generation = newUpstreamTransportGeneration(cfg)
		generation.retired = true
	}
	generation.refs++
	p.transportMu.Unlock()

	if closeIdle != nil {
		closeIdle.closeIdleConnections()
	}
	if closeNow != nil {
		closeNow.close()
	}

	var once sync.Once
	return generation, func() {
		once.Do(func() { p.releaseUpstreamTransportGeneration(generation) })
	}
}

func (p *interceptProxy) releaseUpstreamTransportGeneration(generation *upstreamTransportGeneration) {
	closeNow := false
	p.transportMu.Lock()
	if generation.refs > 0 {
		generation.refs--
	}
	closeNow = generation.retired && generation.refs == 0
	p.transportMu.Unlock()
	if closeNow {
		generation.close()
	}
}

func (p *interceptProxy) closeUpstreamTransports() {
	var closeIdle *upstreamTransportGeneration
	var closeNow *upstreamTransportGeneration
	p.transportMu.Lock()
	if p.upstream != nil {
		p.upstream.retired = true
		if p.upstream.refs == 0 {
			closeNow = p.upstream
		} else {
			closeIdle = p.upstream
		}
		p.upstream = nil
	}
	p.transportMu.Unlock()
	if closeIdle != nil {
		closeIdle.closeIdleConnections()
	}
	if closeNow != nil {
		closeNow.close()
	}
}

func (generation *upstreamTransportGeneration) getHTTPTransport(p *interceptProxy, owner string) (*http.Transport, error) {
	generation.mu.Lock()
	defer generation.mu.Unlock()
	if generation.closed {
		return nil, errors.New("upstream transport generation is closed")
	}
	if transport := generation.httpTransports[owner]; transport != nil {
		return transport, nil
	}
	transport := p.newHTTPTransportForProjectionOwner(generation.projection, owner)
	generation.httpTransports[owner] = transport
	return transport, nil
}

func (generation *upstreamTransportGeneration) closeIdleConnections() {
	generation.mu.Lock()
	if generation.closed {
		generation.mu.Unlock()
		return
	}
	httpTransports := make([]*http.Transport, 0, len(generation.httpTransports))
	for _, transport := range generation.httpTransports {
		httpTransports = append(httpTransports, transport)
	}
	generation.mu.Unlock()

	for _, transport := range httpTransports {
		transport.CloseIdleConnections()
	}
}

func (generation *upstreamTransportGeneration) close() {
	generation.closeOnce.Do(func() {
		generation.mu.Lock()
		generation.closed = true
		httpTransports := make([]*http.Transport, 0, len(generation.httpTransports))
		for _, transport := range generation.httpTransports {
			httpTransports = append(httpTransports, transport)
		}
		generation.httpTransports = nil
		generation.mu.Unlock()

		for _, transport := range httpTransports {
			transport.CloseIdleConnections()
		}
	})
}

func (p *interceptProxy) newHTTPTransport(cfg Config) *http.Transport {
	return p.newHTTPTransportForProjection(newUpstreamTransportProjection(cfg))
}

func (p *interceptProxy) newHTTPTransportForProjection(projection upstreamTransportProjection) *http.Transport {
	return p.newHTTPTransportForProjectionOwner(projection, "")
}

func (p *interceptProxy) newHTTPTransportForProjectionOwner(projection upstreamTransportProjection, owner string) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		ForceAttemptHTTP2:      projection.http2,
		MaxIdleConns:           maxIdleUpstreamHTTPConnections,
		MaxIdleConnsPerHost:    maxIdleUpstreamHTTPConnectionsPerHost,
		IdleConnTimeout:        upstreamHTTPIdleTimeout,
		MaxResponseHeaderBytes: maxModuleNetworkHeaderBytes,
		ResponseHeaderTimeout:  upstreamResponseHeaderTimeout,
		TLSHandshakeTimeout:    upstreamHandshakeTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    p.upstreamRoots,
			// Without a cache every re-dial to an origin is a full handshake
			// through the mihomo leg. The cache belongs to the transport, so it
			// dies with the generation that owns it and never outlives the
			// allowlist that authorized those origins.
			ClientSessionCache: tls.NewLRUClientSessionCache(upstreamSessionCacheEntries),
		},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("upstream TCP target is outside the active extension allowlist")
			}
			target, permitted := projection.targets.upstreamTarget(host, portText, owner)
			if !permitted {
				return nil, errors.New("upstream TCP target is outside the active extension allowlist")
			}
			// dialUpstream enters mihomo through the in-process inner dialer. Bound
			// its connect context so an unresponsive egress cannot hold transport
			// setup indefinitely.
			dialCtx, cancel := context.WithTimeout(ctx, upstreamHandshakeTimeout)
			defer cancel()
			return dialUpstream(dialCtx, target)
		},
	}
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}

func cloneProxyHeaders(source http.Header) http.Header {
	clone := make(http.Header, len(source))
	for name, values := range source {
		clone[name] = append([]string(nil), values...)
	}
	return clone
}

func copyResponseHeaders(destination, source http.Header) {
	for name, values := range source {
		if isHopByHopHeader(name) || connectionListsHeader(source, name) {
			continue
		}
		destination[name] = append([]string(nil), values...)
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if validModuleNetworkHeaderName(name) {
				header.Del(name)
			}
		}
	}
	for name := range header {
		if isHopByHopHeader(name) {
			header.Del(name)
		}
	}
}

func validateNativePatchHeaders(headers http.Header, response bool) error {
	if !response {
		if err := normalizeRequestTEHeader(headers); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !isHopByHopHeader(name) || (!response && strings.EqualFold(name, "Te")) {
			continue
		}
		phase := "request"
		if response {
			phase = "response"
		}
		return fmt.Errorf("header %q is not permitted in a native %s patch", name, phase)
	}
	return nil
}

func sanitizeForwardRequestHeaders(headers http.Header) {
	preserveTrailers := requestTEIsTrailers(headers)
	removeHopByHopHeaders(headers)
	if preserveTrailers {
		headers.Set("Te", "trailers")
	}
}

func requestTEIsTrailers(headers http.Header) bool {
	var values []string
	fields := 0
	for name, fieldValues := range headers {
		if strings.EqualFold(name, "Te") {
			fields++
			values = append(values, fieldValues...)
		}
	}
	return fields == 1 && len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "trailers")
}

func connectionListsHeader(headers http.Header, want string) bool {
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(name), want) {
				return true
			}
		}
	}
	return false
}

func normalizeRequestTEHeader(headers http.Header) error {
	var names []string
	for name := range headers {
		if strings.EqualFold(name, "Te") {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	if len(names) != 1 {
		return fmt.Errorf("duplicate TE header names %q", names)
	}
	values := headers[names[0]]
	if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), "trailers") {
		return errors.New("TE header must contain exactly trailers")
	}
	delete(headers, names[0])
	headers.Set("Te", "trailers")
	return nil
}

func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func validResponseTrailerName(name string) bool {
	if !validModuleNetworkHeaderName(name) {
		return false
	}
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(canonical, "If-") {
		return false
	}
	switch canonical {
	case interceptAltSvcHeader, "Authorization", "Cache-Control", "Connection", "Content-Encoding", "Content-Length", "Content-Range", "Content-Type",
		"Expect", "Host", "Keep-Alive", "Max-Forwards", "Pragma", "Proxy-Authenticate", "Proxy-Authorization",
		"Proxy-Connection", "Range", "Realm", "Te", "Trailer", "Transfer-Encoding", "Www-Authenticate":
		return false
	default:
		return true
	}
}

func responseTrailerNames(trailers http.Header) []string {
	seen := make(map[string]struct{}, len(trailers))
	for name := range trailers {
		canonical := http.CanonicalHeaderKey(name)
		if !validResponseTrailerName(canonical) {
			continue
		}
		seen[canonical] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func declareResponseTrailers(header, trailers http.Header) []string {
	header.Del("Trailer")
	names := responseTrailerNames(trailers)
	if len(names) == 0 {
		return nil
	}
	header.Del("Content-Length")
	header.Set("Trailer", strings.Join(names, ", "))
	return names
}

func publishResponseTrailers(header, trailers http.Header, declared []string) {
	declaredSet := make(map[string]struct{}, len(declared))
	for _, name := range declared {
		declaredSet[name] = struct{}{}
	}
	for _, name := range responseTrailerNames(trailers) {
		values := responseTrailerValues(trailers, name)
		if _, exists := declaredSet[name]; exists {
			header[name] = values
			continue
		}
		header[http.TrailerPrefix+name] = values
	}
}

func responseTrailerValues(trailers http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range trailers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

// The HTTP/2 response writer does not implement io.ReaderFrom, and no upstream
// body implements io.WriterTo, so io.Copy would allocate a fresh 32 KiB buffer
// for every streamed response on that leg. io.CopyBuffer consults
// both interfaces before it looks at the buffer, so the HTTP/1 writer keeps its
// own ReadFrom fast path and never reaches this pool.
//
// Reuse across responses is the only thing new here: io.Copy already reuses one
// buffer for every write of a single response, so a writer that retained the
// slice past Write would have been broken before this change too.
var streamingResponseBuffers = sync.Pool{
	New: func() any {
		buffer := make([]byte, 32<<10)
		return &buffer
	},
}

func writeStreamingProxyResponse(w http.ResponseWriter, downstreamProtoMajor int, method string, response *http.Response) error {
	controller := http.NewResponseController(w)
	announcedTrailers, err := wireTrailers(response.Trailer)
	if err != nil {
		return fmt.Errorf("upstream response trailers: %w", err)
	}
	canHaveBody := responseCanHaveBody(method, response.StatusCode)
	if len(responseTrailerNames(announcedTrailers)) > 0 && !canHaveBody {
		return errors.New("response trailers require a response body section")
	}
	// copyResponseHeaders reads its source and copies every value slice it keeps,
	// so the wireHeaders clone this used to take was garbage by the time it
	// returned -- one map plus one slice per field, on the hot path for every
	// response no action transforms.
	copyResponseHeaders(w.Header(), response.Header)
	declaredTrailers := declareResponseTrailers(w.Header(), announcedTrailers)
	forceChunked := downstreamProtoMajor == 1 && response.ProtoMajor >= 2 && canHaveBody
	if forceChunked {
		w.Header().Del("Content-Length")
	}
	pinInterceptAltSvc(w.Header())
	w.WriteHeader(response.StatusCode)
	if forceChunked {
		if err := controller.Flush(); err != nil {
			return err
		}
	}
	buffer := streamingResponseBuffers.Get().(*[]byte)
	defer streamingResponseBuffers.Put(buffer)
	streamed := &transferDeadlineWriter{Writer: w, controller: controller, timeout: interceptTransferStallTimeout}
	if _, err := io.CopyBuffer(streamed, response.Body, *buffer); err != nil {
		return err
	}
	responseTrailers, err := wireTrailers(response.Trailer)
	if err != nil {
		return fmt.Errorf("upstream response trailers: %w", err)
	}
	if len(responseTrailerNames(responseTrailers)) > 0 && !canHaveBody {
		return errors.New("response trailers require a response body section")
	}
	if len(responseTrailerNames(responseTrailers)) > 0 {
		if err := controller.Flush(); err != nil {
			return err
		}
	}
	publishResponseTrailers(w.Header(), responseTrailers, declaredTrailers)
	return nil
}

func responseCanHaveBody(method string, status int) bool {
	if method == http.MethodHead || status >= 100 && status <= 199 {
		return false
	}
	return status != http.StatusNoContent && status != http.StatusNotModified
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	done := make(chan struct{})
	return &singleConnListener{conn: &closeNotifyConn{Conn: conn, done: done}, done: done}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	accepted := false
	l.once.Do(func() { accepted = true })
	if accepted {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type closeNotifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
