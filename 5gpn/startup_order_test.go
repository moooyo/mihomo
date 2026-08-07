package fivegpn

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/5gpn/api"
	"github.com/metacubex/mihomo/5gpn/engine"
)

func TestInterceptionPlanIsInstalledBeforeDNSListeners(t *testing.T) {
	var order []string
	ensured := false
	planInstalled := false
	err := startInterceptionBeforeDNS(
		func() error {
			order = append(order, "ensure")
			ensured = true
			return nil
		},
		func() error {
			if !ensured {
				t.Fatal("interception install ran before its document was ensured")
			}
			order = append(order, "install")
			planInstalled = true
			return nil
		},
		func() error {
			if !planInstalled {
				t.Fatal("DNS listeners opened before an active or pending interception plan was installed")
			}
			order = append(order, "listen")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ensure", "install", "listen"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("startup order = %v, want %v", order, want)
	}
}

func TestDNSDoesNotListenWhenInterceptionPlanCannotBeBuilt(t *testing.T) {
	sentinel := errors.New("corrupt interception document")
	listenCalled := false
	err := startInterceptionBeforeDNS(
		func() error { return nil },
		func() error { return sentinel },
		func() error {
			listenCalled = true
			return nil
		},
	)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "install interception plan") {
		t.Fatalf("startup error = %v, want wrapped plan error", err)
	}
	if listenCalled {
		t.Fatal("DNS listeners opened after interception plan installation failed")
	}
}

func TestInterceptionCapabilityV5PublishAndWithdraw(t *testing.T) {
	advertiseInterceptionCapability(false)
	t.Cleanup(func() { advertiseInterceptionCapability(false) })
	if _, ok := api.LookupFeature(capabilityInterceptionKey); ok {
		t.Fatal("withdrawn interception capability remains advertised")
	}

	advertiseInterceptionCapability(true)
	feature, ok := api.LookupFeature(capabilityInterceptionKey)
	if !ok || feature.Version != 5 {
		t.Fatalf("advertised interception capability = %+v, present %v; want version 5", feature, ok)
	}

	advertiseInterceptionCapability(false)
	if _, ok := api.LookupFeature(capabilityInterceptionKey); ok {
		t.Fatal("interception capability remains advertised after withdrawal")
	}
}

func TestPendingCaptureClaimReachesDNS(t *testing.T) {
	capture := captureBindingForDNS(engine.CaptureBinding{
		ModuleID: "example", Pattern: "api.example.com", CaptureDNS: "trust",
		Claimed: true, Ready: false,
	})
	if !capture.Claimed || capture.Ready {
		t.Fatalf("DNS capture = %+v, want claimed pending", capture)
	}
}
