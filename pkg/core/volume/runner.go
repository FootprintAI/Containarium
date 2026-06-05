package volume

import (
	"fmt"
	"os/exec"
	"strings"
)

// CLIRunner is the production Runner: it shells out to the host's `incus`
// binary, the same path the rest of the storage code uses. Combined
// stdout+stderr is returned so command failures carry Incus's own message.
type CLIRunner struct {
	bin string
}

// NewCLIRunner locates `incus` on PATH.
func NewCLIRunner() (*CLIRunner, error) {
	bin, err := exec.LookPath("incus")
	if err != nil {
		return nil, fmt.Errorf("incus not found on PATH (required for shared volumes): %w", err)
	}
	return &CLIRunner{bin: bin}, nil
}

// Run executes `incus <args...>`.
func (r *CLIRunner) Run(args ...string) (string, error) {
	// #nosec G204 -- bin is resolved via exec.LookPath("incus"); args are
	// fixed verbs plus validated volume/pool/container names and paths.
	out, err := exec.Command(r.bin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("incus %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
