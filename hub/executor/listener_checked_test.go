package executor

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type checkedTestInboundConfig struct{}

func (checkedTestInboundConfig) Name() string { return "checked-test" }

func (checkedTestInboundConfig) Equal(other C.InboundConfig) bool {
	_, ok := other.(checkedTestInboundConfig)
	return ok
}

type checkedTestInboundListener struct {
	err error
}

func (*checkedTestInboundListener) Name() string            { return "checked-test" }
func (*checkedTestInboundListener) Address() string         { return "" }
func (*checkedTestInboundListener) RawAddress() string      { return "" }
func (*checkedTestInboundListener) Close() error            { return nil }
func (*checkedTestInboundListener) Config() C.InboundConfig { return checkedTestInboundConfig{} }
func (l *checkedTestInboundListener) Listen(C.Tunnel) error { return l.err }

func TestUpdateListenersCheckedReturnsNamedListenerBindFailure(t *testing.T) {
	bindErr := errors.New("bind failed")
	listeners := map[string]C.InboundListener{
		"checked-test": &checkedTestInboundListener{err: bindErr},
	}
	if err := updateListeners(nil, listeners, false, true); !errors.Is(err, bindErr) {
		t.Fatalf("checked listener update error = %v, want bind failure", err)
	}
}
