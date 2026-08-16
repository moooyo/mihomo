package statevalidator

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
)

type cliSuccess struct {
	Status string `json:"status"`
	Result
}

type cliError struct {
	Status string `json:"status"`
	Code   string `json:"code"`
	Error  string `json:"error"`
}

// Main runs the read-only state validator against the process standard output.
func Main(args []string) {
	if code := Run(args, os.Stdout); code != 0 {
		os.Exit(code)
	}
}

// Run executes one state-validator command and writes exactly one JSON value.
func Run(args []string, stdout io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		return writeCLIError(stdout, "invalid_input", errors.New("usage: 5gpn-state validate [--owner-uid <uid>] <absolute-state-dir>"))
	}
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ownerUID := flags.Int("owner-uid", -1, "expected Unix owner UID for every present state file")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
		return writeCLIError(stdout, "invalid_input", errors.New("usage: 5gpn-state validate [--owner-uid <uid>] <absolute-state-dir>"))
	}
	ownerUIDProvided := false
	flags.Visit(func(current *flag.Flag) {
		if current.Name == "owner-uid" {
			ownerUIDProvided = true
		}
	})
	if ownerUIDProvided && *ownerUID < 0 {
		return writeCLIError(stdout, "invalid_input", errors.New("owner-uid must be a non-negative Unix UID"))
	}

	var (
		result Result
		err    error
	)
	if ownerUIDProvided {
		result, err = ValidateForOwner(flags.Arg(0), *ownerUID)
	} else {
		result, err = Validate(flags.Arg(0))
	}
	if err != nil {
		return writeCLIError(stdout, "invalid_state", err)
	}
	if err := json.NewEncoder(stdout).Encode(cliSuccess{Status: "ok", Result: result}); err != nil {
		return 1
	}
	return 0
}

func writeCLIError(stdout io.Writer, code string, err error) int {
	_ = json.NewEncoder(stdout).Encode(cliError{Status: "error", Code: code, Error: err.Error()})
	return 1
}
