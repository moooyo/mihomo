package engine

// CaptureBinding is what one enabled extension declares about a hostname: that
// it captures it, and which resolver group its origin should be looked up in.
//
// It exists so the DNS engine can answer two questions without importing this
// package's document types -- "is this name steered because an extension asked
// for it" and "which group re-resolves its origin" -- and so a diagnostic can
// name the extension responsible instead of reporting an anonymous verdict.
type CaptureBinding struct {
	ModuleID   string
	ModuleName string
	// Pattern is the declaration that matched, as written: an exact host or a
	// "*.example.com" wildcard.
	Pattern string
	// CaptureDNS is the operator's china/trust binding for this extension.
	CaptureDNS string
	// Claimed means the extension is authorized and the master is on. DNS keeps
	// steering this name to the gateway even when Ready is false so the client
	// traffic backstop can reject it; falling through to an origin answer would
	// silently bypass the operator's authorization.
	Claimed bool
	// Ready reports that the interception master is on, so capture will
	// actually happen. A declaration with the master off is still returned:
	// the extensions page shows the extension as enabled, and an operator
	// asking why the name is not captured needs the master switch named rather
	// than an empty answer.
	Ready bool
}

// ExtensionRuntimeState distinguishes an operator's persisted authorization
// from the derived runtime plan. Only active means new traffic can enter the
// extension; every other phase is fail-closed without rewriting Enabled.
type ExtensionRuntimeState struct {
	Ready  bool   `json:"ready"`
	Phase  string `json:"phase"`
	Reason string `json:"reason,omitempty"`
}

// CaptureFor resolves host against every enabled extension's capture hosts.
//
// Ownership is by execution order: the first enabled extension in
// ExecutionOrder that declared an overlapping pattern wins, and within one
// extension an exact declaration is reported over a wildcard. This is not
// "most specific pattern wins" -- reordering extensions is a reviewed
// transaction precisely because it changes which one owns an overlapping host,
// and therefore which operator-selected group re-resolves its origin.
func (e *Engine) CaptureFor(host string) (CaptureBinding, bool) {
	if e == nil {
		return CaptureBinding{}, false
	}
	cfg, err := e.config.Current()
	if err != nil {
		return CaptureBinding{}, false
	}
	host = canonicalHost(host)
	if host == "" {
		return CaptureBinding{}, false
	}

	byID := make(map[string]Module, len(cfg.Modules))
	for _, m := range cfg.Modules {
		byID[m.ID] = m
	}
	traffic, trafficErr := trafficPolicyForConfig(cfg)
	certificateReady := e.certificateRuntimeReady(cfg)

	consider := func(m Module) (CaptureBinding, bool) {
		if !m.Enabled {
			return CaptureBinding{}, false
		}
		matched := ""
		for _, pattern := range m.CaptureHosts {
			if !matchHostPattern(pattern, host) {
				continue
			}
			// An exact declaration is the more precise statement of what this
			// extension asked for, so it is what the diagnostic reports.
			if matched == "" || pattern == host {
				matched = pattern
			}
			if pattern == host {
				break
			}
		}
		if matched == "" {
			return CaptureBinding{}, false
		}
		ready := cfg.MITM.Enabled && certificateReady && e.clientBoundaryIsReady() && e.moduleEgressReady(m) &&
			trafficErr == nil && e.captureDestinationReady(traffic, host)
		return CaptureBinding{
			ModuleID:   m.ID,
			ModuleName: m.Name,
			Pattern:    matched,
			CaptureDNS: m.CaptureDNS,
			Ready:      ready,
			Claimed:    cfg.MITM.Enabled,
		}, true
	}

	seen := make(map[string]struct{}, len(cfg.ExecutionOrder))
	for _, id := range cfg.ExecutionOrder {
		seen[id] = struct{}{}
		if binding, ok := consider(byID[id]); ok {
			return binding, true
		}
	}
	// A module absent from the order is a document written by something other
	// than this program. Considering it last keeps the ordered ones
	// authoritative while still reporting a capture that will happen.
	for _, m := range cfg.Modules {
		if _, ordered := seen[m.ID]; ordered {
			continue
		}
		if binding, ok := consider(m); ok {
			return binding, true
		}
	}
	return CaptureBinding{}, false
}

// ExtensionRuntimeState reports one module's derived lifecycle without
// persisting a second active bit. Enabled remains the desired authorization.
func (e *Engine) ExtensionRuntimeState(moduleID string) ExtensionRuntimeState {
	if e == nil || e.config == nil {
		return ExtensionRuntimeState{Phase: "disabled", Reason: "engine_unavailable"}
	}
	cfg, err := e.config.Current()
	if err != nil {
		return ExtensionRuntimeState{Phase: "disabled", Reason: "configuration_unavailable"}
	}
	return e.extensionRuntimeStateForConfig(cfg, moduleID)
}

func (e *Engine) extensionRuntimeStateForConfig(cfg Config, moduleID string) ExtensionRuntimeState {
	var module *Module
	for index := range cfg.Modules {
		if cfg.Modules[index].ID == moduleID {
			candidate := cfg.Modules[index]
			module = &candidate
			break
		}
	}
	if module == nil || !module.Enabled {
		return ExtensionRuntimeState{Phase: "disabled"}
	}
	if !cfg.MITM.Enabled {
		return ExtensionRuntimeState{Phase: "armed", Reason: "master_disabled"}
	}
	certificate := e.certificateRuntimeStateForConfig(cfg)
	if certificate.Status == "error" {
		return ExtensionRuntimeState{Phase: "certificate_error", Reason: "certificate_error"}
	}
	if !certificate.Ready {
		return ExtensionRuntimeState{Phase: "certificate_pending", Reason: "certificate_pending"}
	}
	if !e.clientBoundaryIsReady() {
		return ExtensionRuntimeState{Phase: "boundary_unavailable", Reason: "fixed_boundary_unavailable"}
	}
	if !e.moduleEgressReady(*module) {
		return ExtensionRuntimeState{Phase: "egress_unavailable", Reason: "egress_unavailable"}
	}
	policy, err := trafficPolicyForConfig(cfg)
	if err != nil {
		return ExtensionRuntimeState{Phase: "egress_unavailable", Reason: "traffic_policy_unavailable"}
	}
	for _, pattern := range module.CaptureHosts {
		probe := pattern
		if len(pattern) > 2 && pattern[:2] == "*." {
			probe = "runtime-ready." + pattern[2:]
		}
		if !e.captureDestinationReady(policy, probe) {
			return ExtensionRuntimeState{Phase: "egress_unavailable", Reason: "egress_unavailable"}
		}
	}
	return ExtensionRuntimeState{Ready: true, Phase: "active"}
}

// EnabledCount is how many extensions are enabled, so a diagnostic can say
// "three enabled, none declared this name" rather than only "no match".
func (e *Engine) EnabledCount() int {
	if e == nil {
		return 0
	}
	cfg, err := e.config.Current()
	if err != nil {
		return 0
	}
	n := 0
	for _, m := range cfg.Modules {
		if m.Enabled {
			n++
		}
	}
	return n
}
