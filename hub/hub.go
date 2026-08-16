package hub

import (
	"errors"
	"reflect"

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

// ApplyConfig preserves the ordinary mihomo configuration path. It does not
// install the managed 5gpn subsystems or impose their override policy.
func ApplyConfig(cfg *config.Config) error {
	return route.ApplyConfig(cfg, true)
}

func applyManagedConfig(cfg *config.Config) error {
	return applyManagedConfigWith(cfg, startFiveGPN, func(candidate *config.Config) error {
		return route.ApplyConfig(candidate, true)
	})
}

func applyManagedConfigWith(cfg *config.Config, start func() error, apply func(*config.Config) error) error {
	controller, externalUI := route.ConfigFromCore(cfg)
	if err := route.PreflightManagedController(controller, externalUI); err != nil {
		return err
	}
	prepareFiveGPNDistribution()
	if err := start(); err != nil {
		return err
	}
	if err := apply(cfg); err != nil {
		return err
	}
	return nil
}

// Parse is the ordinary mihomo startup path.
func Parse(configBytes []byte, options ...Option) error {
	cfg, err := parseConfig(configBytes)
	if err != nil {
		return err
	}
	applyOptions(cfg, options...)
	return ApplyConfig(cfg)
}

// ParseManaged applies the managed-distribution override policy before any
// 5gpn listener opens. Ordinary mihomo callers continue to use Parse.
func ParseManaged(configBytes []byte, options ...Option) error {
	cfg, err := parseConfig(configBytes)
	if err != nil {
		return err
	}
	if err := applyManagedOptions(cfg, options...); err != nil {
		return err
	}
	return applyManagedConfig(cfg)
}

func parseConfig(configBytes []byte) (*config.Config, error) {
	var cfg *config.Config
	var err error

	if len(configBytes) != 0 {
		cfg, err = executor.ParseWithBytes(configBytes)
	} else {
		cfg, err = executor.Parse()
	}

	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func applyOptions(cfg *config.Config, options ...Option) {
	for _, option := range options {
		if option != nil {
			option(cfg)
		}
	}
}

type managedControllerProjection struct {
	Controller route.Config
	ExternalUI string
}

func snapshotManagedController(cfg *config.Config) managedControllerProjection {
	controller, externalUI := route.ConfigFromCore(cfg)
	snapshot := *controller
	snapshot.Cors.AllowOrigins = append([]string(nil), controller.Cors.AllowOrigins...)
	return managedControllerProjection{Controller: snapshot, ExternalUI: externalUI}
}

func applyManagedOptions(cfg *config.Config, options ...Option) error {
	before := snapshotManagedController(cfg)
	applyOptions(cfg, options...)
	after := snapshotManagedController(cfg)
	if !reflect.DeepEqual(before, after) {
		return errors.New("managed 5gpn controller, TLS, and external-ui values must come from config.yaml without command-line overrides")
	}
	return nil
}
