package agentbox

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// AGENTBOX_ROOT, when set, restricts every file-ops tool to paths that
// resolve under it. It's the strict floor — even if the MCP client
// advertises broader roots via roots/list, AGENTBOX_ROOT still wins.
//
// When AGENTBOX_ROOT is unset and the MCP client supports the roots
// capability, agent-box asks the client (via roots/list) for the
// directories it cares about and uses those as the effective sandbox.
// This matches what filesystem MCP servers in the wild do — agents
// running Cursor or Claude Code get a sandbox aligned with their
// workspace without the operator setting AGENTBOX_ROOT manually.
//
// When neither AGENTBOX_ROOT is set NOR the client supports roots,
// agent-box runs unconstrained (current behavior preserved).
const sandboxRootEnv = "AGENTBOX_ROOT"

var (
	sandboxOnce sync.Once
	sandboxRoot string // empty = no AGENTBOX_ROOT configured

	// mcpServer is the *MCPServer instance set in RegisterTools. It's
	// kept package-level rather than threaded through every handler
	// because nearly every file-ops tool needs to call RequestRoots,
	// and threading through 6 handlers + their tests for one optional
	// call is more churn than it earns. nil when not registered (e.g.
	// in unit tests that exercise handlers directly).
	mcpServer *server.MCPServer
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

// validatePathCtx is the roots-aware path validator. AGENTBOX_ROOT is
// the strict floor; if it's unset and the MCP client advertises roots
// via roots/list, those become the sandbox. Falls back to no
// constraint only when both are absent.
func validatePathCtx(ctx context.Context, p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", p, err)
	}
	abs = filepath.Clean(abs)

	// AGENTBOX_ROOT is the floor. If it's set, that's the only check.
	// Client roots that fall outside it are intentionally ignored —
	// the operator's intent overrides the client's hint.
	if root := resolvedSandboxRoot(); root != "" {
		if abs == root || strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			return abs, nil
		}
		return "", fmt.Errorf("path %q is outside AGENTBOX_ROOT (%s)", p, root)
	}

	// No AGENTBOX_ROOT — try client roots if the server reference is
	// available and the client supports the capability.
	roots := clientRoots(ctx)
	if len(roots) == 0 {
		// Neither AGENTBOX_ROOT nor client roots — unconstrained
		// (preserves current behavior for clients that don't advertise
		// roots).
		return abs, nil
	}
	if pathUnderAny(abs, roots) {
		return abs, nil
	}
	return "", fmt.Errorf("path %q is not under any client-advertised root: %s",
		p, strings.Join(roots, ", "))
}

// clientRoots fetches the MCP client's roots, returning the list of
// filesystem paths or an empty slice if anything goes wrong (no
// session, client doesn't support roots, transport error, malformed
// URI). Empty slice means "don't apply a client-roots constraint."
//
// We deliberately swallow errors here rather than propagate them to
// the agent: the client either supports roots or it doesn't, and
// failing every file op because the client speaks an older MCP version
// is worse UX than just running unconstrained. The operator can still
// set AGENTBOX_ROOT for a hard floor.
func clientRoots(ctx context.Context) []string {
	if mcpServer == nil {
		return nil
	}
	res, err := mcpServer.RequestRoots(ctx, mcp.ListRootsRequest{})
	if err != nil {
		// ErrNoClientSession or ErrRootsNotSupported is the common case.
		// Anything else (transport error) we also treat as "no roots."
		if errors.Is(err, server.ErrNoClientSession) || errors.Is(err, server.ErrRootsNotSupported) {
			return nil
		}
		return nil
	}
	return rootURIsToPaths(res.Roots)
}

// rootURIsToPaths converts a slice of mcp.Root (each carrying a file://
// URI per the MCP spec) into clean absolute filesystem paths. URIs
// that don't parse, or use a non-file scheme, are dropped — the spec
// reserves space for other schemes but the only one defined today is
// file://.
func rootURIsToPaths(roots []mcp.Root) []string {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		u, err := url.Parse(r.URI)
		if err != nil || u.Scheme != "file" {
			continue
		}
		// file:///abs/path → u.Path = /abs/path
		// file://localhost/abs/path → also u.Path = /abs/path
		p := u.Path
		if p == "" {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// pathUnderAny returns true if abs is equal to or contained within
// any of the given roots. Boundary-aware (prefix + separator) so
// /srv/box-evil isn't accidentally accepted under /srv/box.
func pathUnderAny(abs string, roots []string) bool {
	for _, r := range roots {
		if abs == r || strings.HasPrefix(abs, r+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// validatePathAgainstRoots is the testable core: pure function over
// (path, AGENTBOX_ROOT-or-empty). validatePath calls this with
// AGENTBOX_ROOT resolved; tests can invoke it with a synthetic root.
func validatePathAgainstRoots(p, root string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", p, err)
	}
	abs = filepath.Clean(abs)

	if root == "" {
		root = resolvedSandboxRoot()
	}
	if root == "" {
		return abs, nil
	}
	if abs == root || strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return abs, nil
	}
	return "", fmt.Errorf("path %q is outside AGENTBOX_ROOT (%s)", p, root)
}

// resetSandboxOnceForTest clears the cached resolution so a test that
// sets AGENTBOX_ROOT via t.Setenv re-reads it on the next validatePath
// call. Production code should never invoke this — sync.Once is
// intentional for the runtime path so the env is read exactly once per
// process.
func resetSandboxOnceForTest() {
	sandboxOnce = sync.Once{}
	sandboxRoot = ""
}
