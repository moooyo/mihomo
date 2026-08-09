package hub

import (
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalController = externalController
	}
}

func WithExternalControllerTLS(externalControllerTLS string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerTLS = externalControllerTLS
	}
}

func WithExternalControllerUnix(externalControllerUnix string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerUnix = externalControllerUnix
	}
}

func WithExternalControllerPipe(externalControllerPipe string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerPipe = externalControllerPipe
	}
}

func WithExternalControllerRoutingMark(externalControllerRoutingMark int) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerRoutingMark = externalControllerRoutingMark
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.Secret = secret
	}
}

// ApplyConfig dispatch configure to all parts include ExternalController
func ApplyConfig(cfg *config.Config) error {
	if err := startFiveGPN(); err != nil {
		return err
	}
	if err := route.ApplyConfig(cfg, true); err != nil {
		return err
	}
	return nil
}

// Parse call at the beginning of mihomo
func Parse(configBytes []byte, options ...Option) error {
	var cfg *config.Config
	var err error

	if len(configBytes) != 0 {
		cfg, err = executor.ParseWithBytes(configBytes)
	} else {
		cfg, err = executor.Parse()
	}

	if err != nil {
		return err
	}

	for _, option := range options {
		option(cfg)
	}

	return ApplyConfig(cfg)
}
