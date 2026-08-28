package listener

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type managedTestInboundConfig struct {
	name  string
	value string
}

func (c managedTestInboundConfig) Name() string { return c.name }

func (c managedTestInboundConfig) Equal(other C.InboundConfig) bool {
	candidate, ok := other.(managedTestInboundConfig)
	return ok && c == candidate
}

type managedTestOtherInboundConfig managedTestInboundConfig

func (c managedTestOtherInboundConfig) Name() string { return c.name }

func (c managedTestOtherInboundConfig) Equal(other C.InboundConfig) bool {
	switch candidate := other.(type) {
	case managedTestInboundConfig:
		return c.name == candidate.name && c.value == candidate.value
	case managedTestOtherInboundConfig:
		return c == candidate
	default:
		return false
	}
}

type managedTestInboundListener struct {
	config     C.InboundConfig
	listenErr  error
	listens    int
	closes     int
	closePanic bool
}

func (l *managedTestInboundListener) Name() string            { return l.config.Name() }
func (l *managedTestInboundListener) Address() string         { return "" }
func (l *managedTestInboundListener) RawAddress() string      { return "" }
func (l *managedTestInboundListener) Config() C.InboundConfig { return l.config }
func (l *managedTestInboundListener) Close() error {
	l.closes++
	if l.closePanic {
		panic("close before initialization")
	}
	return nil
}
func (l *managedTestInboundListener) Listen(tunnel C.Tunnel) error { l.listens++; return l.listenErr }

func TestInboundListenerProjectionIsOrderIndependentAndSemantic(t *testing.T) {
	first := map[string]C.InboundListener{
		"beta":  &managedTestInboundListener{config: managedTestInboundConfig{name: "beta", value: "two"}},
		"alpha": &managedTestInboundListener{config: managedTestInboundConfig{name: "alpha", value: "one"}},
	}
	second := map[string]C.InboundListener{
		"alpha": &managedTestInboundListener{config: managedTestInboundConfig{name: "alpha", value: "one"}},
		"beta":  &managedTestInboundListener{config: managedTestInboundConfig{name: "beta", value: "two"}},
	}
	if !ProjectInboundListeners(first).Equal(ProjectInboundListeners(second)) {
		t.Fatal("equivalent named listeners produced different projections")
	}

	second["beta"] = &managedTestInboundListener{config: managedTestInboundConfig{name: "beta", value: "changed"}}
	if ProjectInboundListeners(first).Equal(ProjectInboundListeners(second)) {
		t.Fatal("a listener configuration change was absent from the projection")
	}
	delete(second, "beta")
	if ProjectInboundListeners(first).Equal(ProjectInboundListeners(second)) {
		t.Fatal("a removed listener was absent from the projection")
	}
	second["beta"] = &managedTestInboundListener{config: managedTestOtherInboundConfig{name: "beta", value: "two"}}
	if ProjectInboundListeners(first).Equal(ProjectInboundListeners(second)) {
		t.Fatal("a listener type change was absent from the projection")
	}
}

func TestPatchInboundListenersCheckedReturnsBindFailureAndRollsBack(t *testing.T) {
	restore := isolateInboundListeners(t)
	defer restore()

	bindErr := errors.New("bind failed")
	started := &managedTestInboundListener{config: managedTestInboundConfig{name: "alpha", value: "one"}}
	failed := &managedTestInboundListener{
		config:     managedTestInboundConfig{name: "beta", value: "two"},
		listenErr:  bindErr,
		closePanic: true,
	}
	err := PatchInboundListenersChecked(map[string]C.InboundListener{
		"beta":  failed,
		"alpha": started,
	}, nil, true)
	if !errors.Is(err, bindErr) {
		t.Fatalf("checked patch error = %v, want bind failure", err)
	}
	if started.listens != 1 || started.closes != 1 {
		t.Fatalf("started listener lifecycle = listens %d, closes %d, want 1/1", started.listens, started.closes)
	}
	if failed.listens != 1 || failed.closes != 1 {
		t.Fatalf("failed listener lifecycle = listens %d, closes %d, want 1/1", failed.listens, failed.closes)
	}
	if len(inboundListeners) != 0 {
		t.Fatalf("checked patch retained %d listeners after failure", len(inboundListeners))
	}
}

func TestPatchInboundListenersCheckedRejectsReplacementBeforeStartingAdditions(t *testing.T) {
	restore := isolateInboundListeners(t)
	defer restore()

	active := &managedTestInboundListener{config: managedTestInboundConfig{name: "beta", value: "old"}}
	inboundListeners["beta"] = active
	addition := &managedTestInboundListener{config: managedTestInboundConfig{name: "alpha", value: "new"}}
	replacement := &managedTestInboundListener{config: managedTestInboundConfig{name: "beta", value: "new"}}
	if err := PatchInboundListenersChecked(map[string]C.InboundListener{
		"alpha": addition,
		"beta":  replacement,
	}, nil, true); err == nil {
		t.Fatal("checked patch replaced an active listener")
	}
	if addition.listens != 0 || replacement.listens != 0 || active.closes != 0 {
		t.Fatal("checked replacement rejection mutated listener state")
	}
	if inboundListeners["beta"] != active || len(inboundListeners) != 1 {
		t.Fatal("checked replacement rejection changed the active registry")
	}
}

func TestPatchInboundListenersKeepsOrdinaryFailureCompatibility(t *testing.T) {
	restore := isolateInboundListeners(t)
	defer restore()

	failed := &managedTestInboundListener{
		config:    managedTestInboundConfig{name: "ordinary", value: "one"},
		listenErr: errors.New("bind failed"),
	}
	PatchInboundListeners(map[string]C.InboundListener{"ordinary": failed}, nil, true)
	if failed.listens != 1 {
		t.Fatal("ordinary patch did not attempt to start the listener")
	}
	if _, ok := inboundListeners["ordinary"]; ok {
		t.Fatal("ordinary patch published a listener that failed to start")
	}
}

func isolateInboundListeners(t *testing.T) func() {
	t.Helper()
	inboundMux.Lock()
	previous := inboundListeners
	inboundListeners = map[string]C.InboundListener{}
	inboundMux.Unlock()
	return func() {
		inboundMux.Lock()
		for _, listener := range inboundListeners {
			_ = listener.Close()
		}
		inboundListeners = previous
		inboundMux.Unlock()
	}
}
