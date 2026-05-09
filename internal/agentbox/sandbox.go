package agentbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// AGENTBOX_ROOT, when set, restricts every file-ops tool to paths that
// resolve under it. Unset means no constraint — the agent has the same
// reach as the host process. Production deployments set it to the project
// directory so a misbehaving agent can't touch /etc, $HOME/.ssh, etc.
const sandboxRootEnv = "AGENTBOX_ROOT"

var (
	sandboxOnce sync.Once
	sandboxRoot string // empty = unconstrained
)

func resolvedSandboxRoot() string {
	sandboxOnce.Do(func() {
		raw := os.Getenv(sandboxRootEnv)
		if raw == "" {
			return
		}
		abs, err := filepath.Abs(raw)
		if err != nil {
			// Fail closed: a configured-but-unparseable root must not
			// silently degrade to "no constraint."
			sandboxRoot = raw
			return
		}
		sandboxRoot = filepath.Clean(abs)
	})
	return sandboxRoot
}

// validatePath returns the cleaned absolute path if it is allowed under
// the configured sandbox root (or any path, when no root is set). Returns
// a structured error otherwise. Callers should pass the result back to
// os.* operations — using the returned canonical path keeps later error
// messages consistent.
func validatePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", p, err)
	}
	abs = filepath.Clean(abs)

	root := resolvedSandboxRoot()
	if root == "" {
		return abs, nil
	}
	if abs == root {
		return abs, nil
	}
	// Boundary-aware prefix check: root="/srv/box", abs="/srv/box-evil"
	// must not match. Append the separator before comparing.
	if strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return abs, nil
	}
	return "", fmt.Errorf("path %q is outside AGENTBOX_ROOT (%s)", p, root)
}

// resetSandboxOnceForTest clears the cached resolution so a test that sets
// AGENTBOX_ROOT via t.Setenv re-reads it on the next validatePath call.
// Production code should never invoke this — sync.Once is intentional for
// the runtime path so the env is read exactly once per process.
func resetSandboxOnceForTest() {
	sandboxOnce = sync.Once{}
	sandboxRoot = ""
}
