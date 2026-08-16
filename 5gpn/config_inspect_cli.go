package fivegpn

import "github.com/metacubex/mihomo/5gpn/configinspect"

// ConfigInspectMain runs the local, root-only controller config inspector.
func ConfigInspectMain(args []string) {
	configinspect.Main(args)
}
