// Package depprobe exists only to prove that the absorbed engine's dependency
// set resolves and compiles alongside mihomo's. It is deleted once 5gpn/engine
// imports these for real.
package depprobe

import (
	"github.com/andybalholm/cascadia"
	"github.com/dop251/goja"
	"github.com/itchyny/gojq"
	"github.com/miekg/dns"
)

var (
	_ = goja.New
	_ = gojq.Parse
	_ = cascadia.Compile
	_ = dns.Msg{}
)
