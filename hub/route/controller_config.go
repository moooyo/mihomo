package route

import (
	"errors"
	"fmt"
	"sync"

	"github.com/metacubex/mihomo/component/updater"
	coreconfig "github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"
)

var (
	configApplyMu sync.Mutex
	// managedNamedListenerProjection is guarded by configApplyMu.
	managedNamedListenerProjection *listener.InboundListenerProjection
)

// ErrNamedListenersRestartRequired identifies a managed named-listener change
// that is valid only at process startup.
var ErrNamedListenersRestartRequired = errors.New("named listener configuration change requires a process restart")

// ConfigFromCore keeps startup and PUT /configs on one controller projection.
// If these paths construct different candidates, one can accept a document
// that the other silently leaves only partly live.
func ConfigFromCore(cfg *coreconfig.Config) (*Config, string) {
	return &Config{
		Addr:           cfg.Controller.ExternalController,
		TLSAddr:        cfg.Controller.ExternalControllerTLS,
		UnixAddr:       cfg.Controller.ExternalControllerUnix,
		PipeAddr:       cfg.Controller.ExternalControllerPipe,
		RoutingMark:    cfg.Controller.ExternalControllerRoutingMark,
		Secret:         cfg.Controller.Secret,
		Certificate:    cfg.TLS.Certificate,
		PrivateKey:     cfg.TLS.PrivateKey,
		ClientAuthType: cfg.TLS.ClientAuthType,
		ClientAuthCert: cfg.TLS.ClientAuthCert,
		EchKey:         cfg.TLS.EchKey,
		DohServer:      cfg.Controller.ExternalDohServer,
		IsDebug:        cfg.General.LogLevel == log.DEBUG,
		Cors: Cors{
			AllowOrigins:        cfg.Controller.Cors.AllowOrigins,
			AllowPrivateNetwork: cfg.Controller.Cors.AllowPrivateNetwork,
		},
	}, cfg.Controller.ExternalUI
}

// ApplyConfig joins controller publication to the complete executor apply for
// startup and SIGHUP callers outside this package. HTTP PUT/PATCH takes the
// same lock, so no entry points can leave the controller and data plane on
// different config generations.
func ApplyConfig(cfg *coreconfig.Config, force bool) error {
	configApplyMu.Lock()
	defer configApplyMu.Unlock()
	managed := updater.ManagedDistribution()
	projection, err := validateManagedNamedListenerTransition(cfg, managed, false)
	if err != nil {
		return err
	}
	controller, externalUI := ConfigFromCore(cfg)
	if err := ReCreateServer(controller, externalUI); err != nil {
		return err
	}
	if managed {
		if err := executor.ApplyConfigChecked(cfg, force); err != nil {
			return fmt.Errorf("apply managed named listeners: %w", err)
		}
		if managedNamedListenerProjection == nil {
			managedNamedListenerProjection = &projection
		}
	} else {
		executor.ApplyConfig(cfg, force)
	}
	return nil
}

func applyHotConfig(cfg *coreconfig.Config, force bool) error {
	configApplyMu.Lock()
	defer configApplyMu.Unlock()
	managed := updater.ManagedDistribution()
	if _, err := validateManagedNamedListenerTransition(cfg, managed, true); err != nil {
		return err
	}
	controller, externalUI := ConfigFromCore(cfg)
	if err := ReconcileHotServer(controller, externalUI); err != nil {
		return err
	}
	if managed {
		if err := executor.ApplyConfigChecked(cfg, force); err != nil {
			return fmt.Errorf("apply managed named listeners: %w", err)
		}
	} else {
		executor.ApplyConfig(cfg, force)
	}
	return nil
}

func validateManagedNamedListenerTransition(cfg *coreconfig.Config, managed bool, requireLive bool) (listener.InboundListenerProjection, error) {
	if !managed {
		return listener.InboundListenerProjection{}, nil
	}
	projection := listener.ProjectInboundListeners(cfg.Listeners)
	if managedNamedListenerProjection == nil {
		if requireLive {
			return projection, fmt.Errorf("%w: no live managed named-listener projection is available", ErrNamedListenersRestartRequired)
		}
		return projection, nil
	}
	if !managedNamedListenerProjection.Equal(projection) {
		return projection, fmt.Errorf("%w: managed named listeners are startup fields", ErrNamedListenersRestartRequired)
	}
	return projection, nil
}

func lockConfigApply() func() {
	configApplyMu.Lock()
	return configApplyMu.Unlock
}
