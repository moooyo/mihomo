package executor

import (
	"fmt"
	"path/filepath"

	"github.com/metacubex/mihomo/component/overlay"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// coreRevision is the monotonic revision of the overlay's dependency closure.
//
// A commit carries the revision it was validated against; if the closure moved
// in between, the commit conflicts rather than applying against a configuration
// nobody checked it against. It is a counter rather than the digest itself
// because the coordinator has to compare "newer than" as well as "different
// from", and a digest only answers the second.
var (
	coreRevision       uint64
	coreClosureDigest  string
	overlayStateSubdir = "runtime-overlay"
)

// rebindRuntimeOverlay re-checks the active generation against the freshly
// applied configuration.
//
// Config parsing already refused a configuration that cannot evaluate the
// anchors, so the remaining risk is a dependency that vanished — a group
// removed, a processor proxy dropped. That is marked degraded rather than
// fatal: the generation stays active and its captures keep failing closed,
// which is strictly safer than substituting DIRECT.
func rebindRuntimeOverlay(cfg *config.Config) {
	m := tunnel.OverlayManager()
	if m == nil {
		return
	}
	snapshot := m.Snapshot()
	active := snapshot.Active()
	if active == nil {
		return
	}
	if err := validateOverlayDependencies(active, liveDependencyView()); err != nil {
		log.Errorln("[Overlay] active generation %s no longer satisfies the applied configuration: %v", active.Document.GenerationID, err)
		m.MarkDegraded([]string{err.Error()})
		return
	}
	m.MarkDegraded(nil)
}

// CoreRevision returns the current dependency-closure revision.
func CoreRevision() uint64 {
	mux.Lock()
	defer mux.Unlock()
	return coreRevision
}

// coreRevisionLocked is the accessor the overlay manager uses. The commit path
// already holds mux through WithApplyLock, so taking it again here would
// deadlock: sync.Mutex is not reentrant.
func coreRevisionLocked() uint64 { return coreRevision }

// lastOverlayProcessors returns the processor names the most recently applied
// configuration declared. Callers on the commit path hold mux.
func lastOverlayProcessors() map[string]struct{} {
	if appliedProcessors == nil {
		return map[string]struct{}{}
	}
	return appliedProcessors
}

var appliedProcessors map[string]struct{}

// advanceCoreRevisionLocked bumps the revision when the closure actually
// changed. Callers must hold mux.
//
// Bumping unconditionally would make every reload invalidate every in-flight
// commit, including reloads that touch nothing the overlay depends on.
func advanceCoreRevisionLocked(closure overlay.DependencyClosureDigest) {
	sum := closure.Sum()
	if sum == coreClosureDigest {
		return
	}
	coreClosureDigest = sum
	coreRevision++
	log.Debugln("[Overlay] dependency closure changed; core revision is now %d", coreRevision)
}

// WithApplyLock runs fn while excluding a concurrent ApplyConfig.
//
// The overlay commit path uses this so a generation cannot be validated against
// one configuration and published against another. The lock order is
// executor.mux first, tunnel.configMux second — ApplyConfig takes them that way
// and reversing it deadlocks.
func WithApplyLock[T any](fn func() (T, error)) (T, error) {
	mux.Lock()
	defer mux.Unlock()
	return fn()
}

// OverlayStateDir is where generation artifacts live.
func OverlayStateDir() string {
	return filepath.Join(C.Path.HomeDir(), overlayStateSubdir)
}

// EnableRuntimeOverlay opens the durable store and installs the overlay.
//
// It is called once at startup, before the data plane opens. Recovery installs
// the quarantine snapshot: ordinary non-capture routing stays available while
// every known capture match rejects and every processor egress capability is
// disabled. That is the only safe answer to a restart, because a client's DNS
// cache may still point capture hosts at the gateway.
//
// It takes the configuration that is about to be applied rather than reading
// live state, because recovery runs before ApplyConfig: at that point nothing
// has published the processor declarations a persisted generation must be
// recompiled against, and recovery would fail on every restart.
func EnableRuntimeOverlay(cfg *config.Config) error {
	owner := cfg.Controller.RuntimeOverlayOwner
	if owner == "" {
		return nil
	}
	// Idempotent: hub.Parse runs again on every SIGHUP, and re-opening the
	// store would discard the recovered snapshot and the live lease.
	if m := tunnel.OverlayManager(); m != nil && m.Owner() == owner {
		mux.Lock()
		appliedProcessors = cfg.OverlayProcessors
		mux.Unlock()
		return nil
	}
	if err := overlay.ValidateOwner(owner); err != nil {
		return err
	}
	// Publish the incoming configuration's processor set so recovery can
	// recompile against it.
	mux.Lock()
	appliedProcessors = cfg.OverlayProcessors
	mux.Unlock()

	store, err := overlay.OpenStore(OverlayStateDir(), owner)
	if err != nil {
		return err
	}

	manager := overlay.NewManager(store, owner, overlay.Hooks{
		CoreRevision:         coreRevisionLocked,
		LiveCoreRevision:     CoreRevision,
		ProcessorProxies:     processorProxies,
		ValidateDependencies: func(c *overlay.Compiled) error { return validateOverlayDependencies(c, liveDependencyView()) },
		AdvanceResolverEpoch: advanceResolverEpoch,
		RevokeGeneration:     func(id string) { tunnel.RevokeOverlayGeneration(id) },
	})
	tunnel.SetOverlayManager(manager)

	if err := manager.Recover(); err != nil {
		// Refusing is deliberate. Continuing would serve the ordinary path for
		// hosts whose clients still resolve to the gateway, which is precisely
		// the unguarded data plane the design forbids.
		tunnel.SetOverlayManager(nil)
		return fmt.Errorf("runtime overlay recovery failed: %w", err)
	}
	log.Infoln("[Overlay] runtime overlay enabled for owner %q, state in %s", owner, OverlayStateDir())
	return nil
}

// processorProxies reports the proxies the live configuration declared as
// external traffic processors.
func processorProxies() map[string]string {
	names := lastOverlayProcessors()
	out := make(map[string]string, len(names))
	for name := range names {
		out[name] = name
	}
	return out
}

// dependencyView is the state a generation is validated against.
//
// It is passed in rather than read from live globals because the two callers see
// the world at different moments: a commit validates against the running
// configuration, while startup validates against the configuration that is
// about to be applied — at which point tunnel's proxy map is still empty. Every
// earlier version of this read live state and consequently refused every
// restart of a deployment that used capture.
type dependencyView struct {
	proxies    map[string]C.Proxy
	processors map[string]struct{}
	mode       tunnel.TunnelMode
}

func liveDependencyView() dependencyView {
	return dependencyView{
		proxies:    tunnel.Proxies(),
		processors: lastOverlayProcessors(),
		mode:       tunnel.Mode(),
	}
}

func configDependencyView(cfg *config.Config) dependencyView {
	return dependencyView{
		proxies:    cfg.Proxies,
		processors: cfg.OverlayProcessors,
		mode:       cfg.General.Mode,
	}
}

// validateOverlayDependencies checks a compiled generation against a view of
// the configuration it will run under.
//
// Group existence is re-checked here rather than only at parse time because a
// group can disappear through a config reload between staging and commit; the
// commit must then fail closed instead of publishing a generation whose egress
// resolves to nothing.
func validateOverlayDependencies(c *overlay.Compiled, view dependencyView) error {
	if view.mode != tunnel.Rule {
		return fmt.Errorf("%w: tunnel is in %s mode", overlay.ErrModeConflict, view.mode)
	}
	for _, cap := range c.Document.Egress.Capabilities {
		// Every binding is checked, not just the first: a capability is only as
		// safe as its least safe destination, and a group that vanished between
		// staging and commit must fail the commit whichever binding named it.
		for _, bind := range cap.Bindings {
			p, ok := view.proxies[bind.Group]
			if !ok {
				return fmt.Errorf("%w: capability %q names egress group %q, which does not exist", overlay.ErrDependencyMissing, cap.ID, bind.Group)
			}
			if !bind.AllowDirect && p.Type() == C.Direct {
				return fmt.Errorf("%w: capability %q resolves group %q to DIRECT but does not allow it", overlay.ErrDependencyMissing, cap.ID, bind.Group)
			}
			if _, isProcessor := view.processors[bind.Group]; isProcessor {
				return fmt.Errorf("%w: capability %q names the processor %q as its own egress, which would loop", overlay.ErrDependencyMissing, cap.ID, bind.Group)
			}
		}
	}
	for _, t := range c.Document.ProcessorTargets {
		if _, ok := view.proxies[t.Name]; !ok {
			return fmt.Errorf("%w: processor target %q names proxy %q, which does not exist", overlay.ErrDependencyMissing, t.ID, t.Name)
		}
	}
	return nil
}

// advanceResolverEpoch retires every cached DNS answer that predates the
// generation being committed.
//
// It runs inside the commit's critical section, before the snapshot swap, so no
// reader can observe the new generation while the resolver can still answer
// from the previous profile's cache. resolver.ClearCache is unusable here: it
// spawns goroutines and returns before anything is cleared, so it cannot serve
// as a commit fence.
func advanceResolverEpoch(epoch uint64) {
	type epochBumper interface{ BumpEpoch() uint64 }
	bumped := false
	for _, r := range []resolver.Resolver{resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver} {
		if b, ok := r.(epochBumper); ok {
			b.BumpEpoch()
			bumped = true
		}
	}
	if bumped {
		log.Infoln("[Overlay] resolver profile changed; advanced DNS cache epoch to %d", epoch)
	}
}

// ValidateOverlayAgainstConfig refuses a configuration that cannot evaluate a
// generation this process is durably bound to.
//
// The parse-time validator cannot make this call at first boot: the overlay is
// not yet enabled when the initial configuration is parsed, so it has no way to
// know a generation is persisted. This runs after recovery, when it does.
func ValidateOverlayAgainstConfig(cfg *config.Config) error {
	m := tunnel.OverlayManager()
	if m == nil {
		return nil
	}
	snapshot := m.Snapshot()
	if !snapshot.RequiresAnchors() {
		return nil
	}
	if !config.HasOverlayAnchors(cfg.Rules, m.Owner()) {
		return fmt.Errorf("%w: generation %s is persisted but the configuration declares no %q anchors",
			overlay.ErrAnchorInvalid, snapshot.ActiveID(), m.Owner())
	}
	// Validated against the configuration about to be applied, not against live
	// state: at this point in startup nothing has published the proxy map yet.
	return validateOverlayDependencies(snapshot.Active(), configDependencyView(cfg))
}
