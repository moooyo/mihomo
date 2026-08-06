package nodes

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"sync"

	"github.com/metacubex/mihomo/log"
)

type errorOutput struct {
	Code     string `json:"code"`
	Error    string `json:"error"`
	Revision string `json:"revision,omitempty"`
}

var silenceLogsOnce sync.Once

// Main runs the command against the process standard streams.
func Main(args []string) {
	if code := Run(args, os.Stdin, os.Stdout); code != 0 {
		os.Exit(code)
	}
}

// Run executes one local node-management command and writes one JSON value.
func Run(args []string, stdin io.Reader, stdout io.Writer) int {
	silenceLogsOnce.Do(func() { log.SetLevel(log.SILENT) })
	if len(args) == 0 {
		return writeCLIError(stdout, fmtInvalid("a command is required"))
	}

	switch args[0] {
	case "list":
		flags := newFlagSet("list")
		configPath := flags.String("config", "", "operator-owned mihomo config path")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return writeCLIError(stdout, fmtInvalid("invalid list arguments"))
		}
		store, err := New(*configPath)
		if err != nil {
			return writeCLIError(stdout, err)
		}
		view, err := store.List()
		if err != nil {
			return writeCLIError(stdout, err)
		}
		return writeJSON(stdout, view)

	case "import":
		flags := newFlagSet("import")
		configPath := flags.String("config", "", "operator-owned mihomo config path")
		revision := flags.String("revision", "", "raw config SHA-256")
		dryRun := flags.Bool("dry-run", false, "validate without writing")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return writeCLIError(stdout, fmtInvalid("invalid import arguments"))
		}
		content, err := io.ReadAll(io.LimitReader(stdin, MaxImportBytes+1))
		if err != nil {
			return writeCLIError(stdout, errors.New("read import content"))
		}
		if len(content) > MaxImportBytes {
			return writeCLIError(stdout, fmtInvalid("imported content exceeds 1 MiB"))
		}
		store, err := New(*configPath)
		if err != nil {
			return writeCLIError(stdout, err)
		}
		if *dryRun {
			preview, err := store.PreviewImport(*revision, content)
			if err != nil {
				return writeCLIError(stdout, err)
			}
			return writeJSON(stdout, preview)
		}
		result, err := store.Import(*revision, content)
		if err != nil {
			return writeCLIError(stdout, err)
		}
		return writeJSON(stdout, result)

	case "delete":
		flags := newFlagSet("delete")
		configPath := flags.String("config", "", "operator-owned mihomo config path")
		revision := flags.String("revision", "", "raw config SHA-256")
		name := flags.String("name", "", "static proxy name")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return writeCLIError(stdout, fmtInvalid("invalid delete arguments"))
		}
		store, err := New(*configPath)
		if err != nil {
			return writeCLIError(stdout, err)
		}
		result, err := store.Delete(*revision, *name)
		if err != nil {
			return writeCLIError(stdout, err)
		}
		return writeJSON(stdout, result)

	default:
		return writeCLIError(stdout, fmtInvalid("unknown command"))
	}
}

func newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func fmtInvalid(message string) error {
	return &cliInputError{message: message}
}

type cliInputError struct {
	message string
}

func (e *cliInputError) Error() string { return e.message }
func (e *cliInputError) Unwrap() error { return ErrInvalidInput }

func writeCLIError(output io.Writer, err error) int {
	response := errorOutput{Code: "internal_error", Error: "node-management operation failed"}
	var conflict *RevisionConflictError
	switch {
	case errors.As(err, &conflict):
		response.Code = "revision_conflict"
		response.Error = "the mihomo config changed; read it again before retrying"
		response.Revision = conflict.Current
	case errors.Is(err, ErrInvalidInput):
		response.Code = "invalid_input"
		response.Error = err.Error()
	}
	_ = json.NewEncoder(output).Encode(response)
	return 1
}

func writeJSON(output io.Writer, value any) int {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		return 1
	}
	return 0
}
