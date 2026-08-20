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

const (
	containerRuntimeEnvironment = "FIVEGPN_RUNTIME"
	containerRuntimeValue       = "container"
	containerConfigOwnerUID     = 10001
)

var silenceLogsOnce sync.Once

// Main runs the local controller config inspection command.
func Main(args []string) {
	if code := Run(args, os.Stdout); code != 0 {
		os.Exit(code)
	}
}

// Run executes one local inspection and writes exactly one JSON value.
func Run(args []string, stdout io.Writer) int {
	return run(args, stdout, requireConfigInspectionIdentity, readConfigFileForOwner, os.Getenv(containerRuntimeEnvironment))
}

func run(
	args []string,
	stdout io.Writer,
	privilege func(int, bool) error,
	read func(string, int) ([]byte, error),
	runtimeMode string,
) int {
	silenceLogsOnce.Do(func() { log.SetLevel(log.SILENT) })
	if len(args) == 0 || args[0] != "inspect-controller" {
		return writeCLIError(stdout, "invalid_input", "inspect-controller is required")
	}
	flags := flag.NewFlagSet("inspect-controller", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "operator-owned mihomo config path")
	ownerUID := flags.Int("owner-uid", -1, "expected owner UID in the fixed container runtime")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *configPath == "" {
		return writeCLIError(stdout, "invalid_input", "--config is required and no positional arguments are allowed")
	}
	ownerUIDProvided := false
	flags.Visit(func(current *flag.Flag) {
		if current.Name == "owner-uid" {
			ownerUIDProvided = true
		}
	})
	expectedOwnerUID := 0
	containerOwnerMode := false
	if ownerUIDProvided {
		if *ownerUID != containerConfigOwnerUID || runtimeMode != containerRuntimeValue {
			return writeCLIError(stdout, "invalid_input", "--owner-uid is restricted to the fixed container runtime identity")
		}
		expectedOwnerUID = containerConfigOwnerUID
		containerOwnerMode = true
	}
	if err := privilege(expectedOwnerUID, containerOwnerMode); err != nil {
		return writeCLIError(stdout, "permission_denied", "controller config inspection identity is not authorized")
	}
	raw, err := read(*configPath, expectedOwnerUID)
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
