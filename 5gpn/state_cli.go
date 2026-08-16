package fivegpn

import "github.com/metacubex/mihomo/5gpn/statevalidator"

// StateMain runs the local, read-only durable-state validator.
func StateMain(args []string) {
	statevalidator.Main(args)
}
