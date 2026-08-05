package engine

// Snapshot is the read-only view of the interception subsystem that the control
// API serves and the console renders.
//
// It is a projection, not the document. The document carries script bodies and
// manifest text that can run to megabytes, and a list response that shipped
// them would make opening the extensions page expensive in proportion to what
// is installed. Detail reads fetch those individually.
type Snapshot struct {
	Enabled               bool             `json:"enabled"`
	HTTP2                 bool             `json:"http2"`
	HTTP3                 bool             `json:"http3"`
	Modules               []ModuleSummary  `json:"modules"`
	ExecutionOrder        []string         `json:"execution_order"`
	AvailableEgressGroups []string         `json:"available_egress_groups"`
	ActiveCaptureHosts    []string         `json:"active_capture_hosts"`
	Certificate           CertificateState `json:"certificate"`
}

// ModuleSummary is one installed extension, without its bodies.
type ModuleSummary struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	Version      string   `json:"version,omitempty"`
	Enabled      bool     `json:"enabled"`
	CaptureHosts []string `json:"capture_hosts"`
	CaptureDNS   string   `json:"capture_dns"`
	EgressGroup  string   `json:"egress_group,omitempty"`
	// EgressGroupRequired is what makes an empty EgressGroup meaningful.
	EgressGroupRequired bool `json:"egress_group_required"`
}

// CertificateState reports whether the leaf on disk still covers what the
// enabled extensions ask to capture.
//
// This is the one piece of status an operator cannot infer from anywhere else.
// A leaf is issued for the SAN set the enabled extensions needed at the time;
// enabling one more extension widens that set, and until the root oneshot
// reissues, capture for the new host presents a certificate that does not name
// it. The failure looks like a client-side trust error with nothing in the
// gateway's logs, so it has to be visible here.
type CertificateState struct {
	// Loaded means a non-CA leaf and matching private key can be parsed from the
	// current files. It deliberately remains true after expiry so NotAfter can
	// explain why handshakes reject the leaf.
	Loaded     bool     `json:"loaded"`
	NotAfter   int64    `json:"not_after,omitempty"`
	CoveredAll bool     `json:"covers_all_capture_hosts"`
	Missing    []string `json:"missing_hosts,omitempty"`
}

// Snapshot renders the current interception state.
func (e *Engine) Snapshot() (Snapshot, error) {
	cfg, err := e.config.Current()
	if err != nil {
		return Snapshot{}, err
	}

	// Every list here is built with make, never with append onto a nil slice.
	// A nil slice marshals to JSON null, and null is not what this type says it
	// serves: the console reads .length off all three, so a gateway with no
	// extensions installed -- or with the MITM master off -- rendered the
	// extensions page into a TypeError and a blank screen. An empty list and a
	// missing list are different claims, and only one of them is true here.
	out := Snapshot{
		Enabled:               cfg.MITM.Enabled,
		HTTP2:                 cfg.MITM.HTTP2,
		HTTP3:                 cfg.MITM.HTTP3,
		ExecutionOrder:        make([]string, 0, len(cfg.ExecutionOrder)),
		Modules:               make([]ModuleSummary, 0, len(cfg.Modules)),
		AvailableEgressGroups: e.AvailableEgressGroups(),
		ActiveCaptureHosts:    make([]string, 0),
	}
	out.ExecutionOrder = append(out.ExecutionOrder, cfg.ExecutionOrder...)

	for _, m := range cfg.Modules {
		out.Modules = append(out.Modules, summariseModule(m))
	}

	// The active set is what the matcher will actually accept, which is not the
	// union of every installed extension's hosts: a disabled extension declares
	// hosts that nothing captures. Reporting the declared set instead would tell
	// an operator their traffic is being intercepted when it is not.
	if cfg.MITM.Enabled {
		out.ActiveCaptureHosts = append(out.ActiveCaptureHosts, e.readyCaptureHostPatterns(cfg)...)
	}

	out.Certificate = e.certificateState(cfg)
	return out, nil
}

func (e *Engine) certificateState(cfg Config) CertificateState {
	state := CertificateState{}
	status, loaded := e.certs.status(cfg)
	if !loaded {
		return state
	}
	state.Loaded = true
	state.NotAfter = status.notAfter.Unix()

	want := certificateHostPatterns(cfg)
	have := make(map[string]struct{}, len(status.dnsNames))
	for _, name := range status.dnsNames {
		have[canonicalHost(name)] = struct{}{}
	}
	for _, pattern := range want {
		if _, ok := have[canonicalHost(pattern)]; !ok {
			state.Missing = append(state.Missing, pattern)
		}
	}
	state.CoveredAll = len(state.Missing) == 0
	return state
}

func summariseModule(m Module) ModuleSummary {
	return ModuleSummary{
		ID:      m.ID,
		Name:    m.Name,
		Version: m.Version,
		Enabled: m.Enabled,
		// Copied rather than aliased: the summary outlives the read lock the
		// document was taken under, and a caller ranging over it while a reload
		// swaps the document underneath would see a slice whose backing array
		// belongs to a config nobody is serving any more.
		CaptureHosts: append(make([]string, 0, len(m.CaptureHosts)), m.CaptureHosts...),
		CaptureDNS:   m.CaptureDNS,
		EgressGroup:  m.EgressGroup,
		// Reported separately from EgressGroup because the two answer different
		// questions. An empty group on a module that does not require one is
		// fine; on a module that does, it is the reason the module is installed
		// and enabled and still not capturing anything -- a state the console
		// has to be able to name.
		EgressGroupRequired: m.EgressGroupRequired,
	}
}
