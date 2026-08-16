package configinspect

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"sync"

	"github.com/metacubex/mihomo/log"
)

type errorOutput struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

var silenceLogsOnce sync.Once

// Main runs the root-only controller config inspection command.
func Main(args []string) {
	if code := Run(args, os.Stdout); code != 0 {
		os.Exit(code)
	}
}

// Run executes one local inspection and writes exactly one JSON value.
func Run(args []string, stdout io.Writer) int {
	return run(args, stdout, requireRoot, readConfigFile)
}

func run(args []string, stdout io.Writer, privilege func() error, read func(string) ([]byte, error)) int {
	silenceLogsOnce.Do(func() { log.SetLevel(log.SILENT) })
	if len(args) == 0 || args[0] != "inspect-controller" {
		return writeCLIError(stdout, "invalid_input", "inspect-controller is required")
	}
	flags := flag.NewFlagSet("inspect-controller", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "operator-owned mihomo config path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *configPath == "" {
		return writeCLIError(stdout, "invalid_input", "--config is required and no positional arguments are allowed")
	}
	if err := privilege(); err != nil {
		return writeCLIError(stdout, "permission_denied", "controller config inspection requires root")
	}
	raw, err := read(*configPath)
	if err != nil {
		return writeCLIError(stdout, "invalid_config", "operator config could not be read safely")
	}
	view, err := Inspect(raw)
	if err != nil {
		return writeCLIError(stdout, "invalid_config", "operator config does not contain a valid managed controller")
	}
	return writeJSON(stdout, view)
}

func writeCLIError(output io.Writer, code, message string) int {
	_ = json.NewEncoder(output).Encode(errorOutput{Code: code, Error: message})
	return 1
}

func writeJSON(output io.Writer, value any) int {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		return 1
	}
	return 0
}
