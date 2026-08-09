package route

import (
	"sync"

	coreconfig "github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
)

var configApplyMu sync.Mutex

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
	controller, externalUI := ConfigFromCore(cfg)
	if err := ReCreateServer(controller, externalUI); err != nil {
		return err
	}
	executor.ApplyConfig(cfg, force)
	return nil
}

func applyHotConfig(cfg *coreconfig.Config, force bool) error {
	configApplyMu.Lock()
	defer configApplyMu.Unlock()
	controller, externalUI := ConfigFromCore(cfg)
	if err := ReconcileHotServer(controller, externalUI); err != nil {
		return err
	}
	executor.ApplyConfig(cfg, force)
	return nil
}

func lockConfigApply() func() {
	configApplyMu.Lock()
	return configApplyMu.Unlock
}
