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
	// Ready reports that the interception master is on, so capture will
	// actually happen. A declaration with the master off is still returned:
	// the extensions page shows the extension as enabled, and an operator
	// asking why the name is not captured needs the master switch named rather
	// than an empty answer.
	Ready bool
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
		return CaptureBinding{
			ModuleID:   m.ID,
			ModuleName: m.Name,
			Pattern:    matched,
			CaptureDNS: m.CaptureDNS,
			Ready: cfg.MITM.Enabled && e.clientBoundaryIsReady() && e.moduleEgressReady(m) &&
				trafficErr == nil && e.captureDestinationReady(traffic, host),
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
