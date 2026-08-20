package fivegpn

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	containerPublicCertificateHelper    = "/opt/5gpn/scripts/docker-public-cert.sh"
	containerInterceptCertificateHelper = "/opt/5gpn/scripts/docker-intercept-cert.sh"

	certificateManagerDailyInterval = 24 * time.Hour
	certificateManagerDailyJitter   = time.Hour
	certificateRetryMinimum         = time.Minute
	certificateRetryMaximum         = time.Hour
)

type certificateJob uint8

const (
	certificateJobIntercept certificateJob = 1 << iota
	certificateJobPublic
)

type certificateHelperSpec struct {
	Name        string
	Path        string
	Args        []string
	Environment []string
	Timeout     time.Duration
}

var (
	containerCertificateHelperEnvironment = []string{
		"HOME=/nonexistent",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TMPDIR=/tmp",
	}
	interceptCertificateHelperSpec = certificateHelperSpec{
		Name:        "interception certificate",
		Path:        containerInterceptCertificateHelper,
		Args:        []string{"reconcile"},
		Environment: containerCertificateHelperEnvironment,
		Timeout:     2 * time.Minute,
	}
	publicCertificateHelperSpec = certificateHelperSpec{
		Name:        "public certificate",
		Path:        containerPublicCertificateHelper,
		Args:        []string{"renew"},
		Environment: containerCertificateHelperEnvironment,
		Timeout:     30 * time.Minute,
	}
)

type certificateHelperRunner interface {
	Run(context.Context, certificateHelperSpec) error
}

type certificateManagerOptions struct {
	runner        certificateHelperRunner
	onFatal       func(error)
	dailyInterval time.Duration
	retryMinimum  time.Duration
	retryMaximum  time.Duration
	dailyJitter   func() time.Duration
}

// certificateManager is the only process owner for the two trusted Docker
// certificate helpers. One loop chooses and waits for one command at a time;
// neither a request burst nor the daily fallback can create overlapping
// Certbot and interception-signing mutations.
type certificateManager struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	wake    chan struct{}
	runner  certificateHelperRunner
	onFatal func(error)

	dailyInterval time.Duration
	retryMinimum  time.Duration
	retryMaximum  time.Duration
	dailyJitter   func() time.Duration

	mu              sync.Mutex
	pending         certificateJob
	blocked         certificateJob
	lastRun         certificateJob
	closed          bool
	failures        map[certificateJob]uint
	retryGeneration map[certificateJob]uint64
	retryTimers     map[certificateJob]*time.Timer
	terminalErr     error

	lifecycleMu sync.Mutex
	started     bool
	closeOnce   sync.Once
}

func newContainerCertificateManager(onFatal func(error)) (*certificateManager, error) {
	for _, spec := range []certificateHelperSpec{interceptCertificateHelperSpec, publicCertificateHelperSpec} {
		if err := validateContainerCertificateHelper(spec); err != nil {
			return nil, err
		}
	}
	return newCertificateManager(certificateManagerOptions{runner: processCertificateHelperRunner{}, onFatal: onFatal}), nil
}

func validateContainerCertificateHelper(spec certificateHelperSpec) error {
	if !filepath.IsAbs(spec.Path) {
		return fmt.Errorf("5gpn: %s helper path is not absolute", spec.Name)
	}
	info, err := os.Lstat(spec.Path)
	if err != nil {
		return fmt.Errorf("5gpn: inspect %s helper %s: %w", spec.Name, spec.Path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("5gpn: %s helper %s is not a regular non-symlink file", spec.Name, spec.Path)
	}
	permissions := info.Mode().Perm()
	if permissions&0o555 != 0o555 || permissions&0o022 != 0 {
		return fmt.Errorf("5gpn: %s helper %s must be read-executable and not group/other-writable (mode %04o)", spec.Name, spec.Path, permissions)
	}
	return nil
}

func newCertificateManager(options certificateManagerOptions) *certificateManager {
	if options.dailyInterval <= 0 {
		options.dailyInterval = certificateManagerDailyInterval
	}
	if options.retryMinimum <= 0 {
		options.retryMinimum = certificateRetryMinimum
	}
	if options.retryMaximum < options.retryMinimum {
		options.retryMaximum = certificateRetryMaximum
	}
	if options.dailyJitter == nil {
		options.dailyJitter = randomCertificateDailyJitter
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager := &certificateManager{
		ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1),
		runner: options.runner, onFatal: options.onFatal, dailyInterval: options.dailyInterval,
		retryMinimum: options.retryMinimum, retryMaximum: options.retryMaximum,
		dailyJitter:     options.dailyJitter,
		failures:        make(map[certificateJob]uint),
		retryGeneration: make(map[certificateJob]uint64),
		retryTimers:     make(map[certificateJob]*time.Timer),
	}
	manager.schedule(certificateJobIntercept | certificateJobPublic)
	return manager
}

func (m *certificateManager) Start() error {
	if m == nil {
		return errors.New("5gpn: certificate manager is nil")
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return errors.New("5gpn: certificate manager is closed")
	}
	if m.started {
		return nil
	}
	if m.runner == nil {
		return errors.New("5gpn: certificate helper runner is required")
	}
	m.started = true
	go m.run()
	return nil
}

func (m *certificateManager) NotifyIntercept() {
	if m != nil {
		m.schedule(certificateJobIntercept)
	}
}

func (m *certificateManager) schedule(jobs certificateJob) {
	if jobs == 0 {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.pending |= jobs
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *certificateManager) takeNext() certificateJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0
	}
	ready := m.pending &^ m.blocked
	if ready == 0 {
		return 0
	}
	job := certificateJob(0)
	if ready&(certificateJobIntercept|certificateJobPublic) == (certificateJobIntercept | certificateJobPublic) {
		if m.lastRun == certificateJobIntercept {
			job = certificateJobPublic
		} else {
			job = certificateJobIntercept
		}
	} else if ready&certificateJobIntercept != 0 {
		job = certificateJobIntercept
	} else {
		job = certificateJobPublic
	}
	m.pending &^= job
	m.lastRun = job
	return job
}

func (m *certificateManager) run() {
	defer close(m.done)
	daily := time.NewTimer(m.nextDailyDelay())
	defer daily.Stop()
	for {
		// Service the wall-clock deadline even while notifications keep another
		// job continuously pending. Otherwise the fast path below can avoid the
		// blocking select forever and starve public renewal.
		select {
		case <-m.ctx.Done():
			return
		case <-daily.C:
			m.schedule(certificateJobIntercept | certificateJobPublic)
			daily.Reset(m.nextDailyDelay())
		default:
		}
		if job := m.takeNext(); job != 0 {
			m.runJob(job)
			if m.ctx.Err() != nil {
				return
			}
			continue
		}
		select {
		case <-m.ctx.Done():
			return
		case <-m.wake:
		case <-daily.C:
			m.schedule(certificateJobIntercept | certificateJobPublic)
			daily.Reset(m.nextDailyDelay())
		}
	}
}

func (m *certificateManager) nextDailyDelay() time.Duration {
	jitter := time.Duration(0)
	if m.dailyJitter != nil {
		jitter = m.dailyJitter()
	}
	if jitter < 0 {
		jitter = 0
	}
	return m.dailyInterval + jitter
}

func randomCertificateDailyJitter() time.Duration {
	limit := big.NewInt(int64(certificateManagerDailyJitter) + 1)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// Failure to add load spreading must not stop certificate convergence.
		return 0
	}
	return time.Duration(value.Int64())
}

func (m *certificateManager) runJob(job certificateJob) {
	spec := publicCertificateHelperSpec
	if job == certificateJobIntercept {
		spec = interceptCertificateHelperSpec
	}
	ctx, cancel := context.WithTimeout(m.ctx, spec.Timeout)
	log.Infoln("[5GPN/CERT] running %s helper", spec.Name)
	err := m.runner.Run(ctx, spec)
	cancel()
	if errors.Is(err, errCertificateHelperGroupStuck) || errors.Is(err, errCertificateHelperCleanup) {
		failure := fmt.Errorf("5gpn: %s helper isolation cleanup: %w", spec.Name, err)
		log.Errorln("[5GPN/CERT] %v", failure)
		m.mu.Lock()
		if m.terminalErr == nil {
			m.terminalErr = failure
		}
		m.mu.Unlock()
		m.cancel()
		if m.onFatal != nil {
			m.onFatal(failure)
		}
		return
	}
	if m.ctx.Err() != nil {
		return
	}
	if err == nil {
		m.clearRetry(job)
		log.Infoln("[5GPN/CERT] %s helper completed", spec.Name)
		return
	}
	delay, scheduled := m.scheduleRetry(job)
	if scheduled {
		log.Warnln("[5GPN/CERT] %s helper failed: %v; retrying in %s", spec.Name, err, delay)
	}
}

func (m *certificateManager) scheduleRetry(job certificateJob) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, false
	}
	m.failures[job]++
	delay := m.retryMinimum
	for attempt := uint(1); attempt < m.failures[job] && delay < m.retryMaximum; attempt++ {
		if delay > m.retryMaximum/2 {
			delay = m.retryMaximum
			break
		}
		delay *= 2
	}
	if delay > m.retryMaximum {
		delay = m.retryMaximum
	}
	if previous := m.retryTimers[job]; previous != nil {
		previous.Stop()
	}
	m.pending |= job
	m.blocked |= job
	m.retryGeneration[job]++
	generation := m.retryGeneration[job]
	m.retryTimers[job] = time.AfterFunc(delay, func() {
		m.mu.Lock()
		if m.closed || m.retryGeneration[job] != generation {
			m.mu.Unlock()
			return
		}
		m.blocked &^= job
		delete(m.retryTimers, job)
		m.mu.Unlock()
		m.wakeLoop()
	})
	return delay, true
}

func (m *certificateManager) clearRetry(job certificateJob) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures[job] = 0
	m.blocked &^= job
	m.retryGeneration[job]++
	if timer := m.retryTimers[job]; timer != nil {
		timer.Stop()
		delete(m.retryTimers, job)
	}
}

func (m *certificateManager) wakeLoop() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *certificateManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.lifecycleMu.Lock()
		m.mu.Lock()
		m.closed = true
		m.cancel()
		for _, timer := range m.retryTimers {
			timer.Stop()
		}
		m.retryTimers = make(map[certificateJob]*time.Timer)
		m.mu.Unlock()
		started := m.started
		if !started {
			close(m.done)
		}
		m.lifecycleMu.Unlock()
	})
	<-m.done
	m.mu.Lock()
	err := m.terminalErr
	m.mu.Unlock()
	return err
}

var errCertificateHelperUnsupported = errors.New("5gpn: container certificate helpers require Linux")
var errCertificateHelperCleanup = errors.New("certificate helper process-group cleanup failed")
var errCertificateHelperGroupStuck = errors.New("certificate helper process group survived SIGKILL")
