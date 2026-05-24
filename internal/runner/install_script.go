// Package runner provisions Containarium boxes as ephemeral GitHub
// Actions self-hosted runners.
//
// Two entry points share one orchestration helper:
//
//   - internal/cmd/runner.go      → CLI verbs (containarium runner provision/list/remove)
//   - internal/mcp/tools.go       → MCP tools  (provision_runners/list_runners/remove_runner)
//
// Per CLAUDE.md: the CLI is canonical. The MCP tools are thin wrappers
// over the same Go function that the CLI handler calls. Don't make
// the MCP tool talk to a different code path.
package runner

import _ "embed"

// To resync the embedded payload with hacks/runner/install.sh after
// editing the source, run:
//
//   go generate ./internal/runner/...
//
// The TestEmbeddedInstallScriptMatchesSource test enforces the two
// files stay in lockstep — CI catches drift.
//
//go:generate cp ../../hacks/runner/install.sh ./install_script_payload.sh

// InstallScript is the bytes of hacks/runner/install.sh embedded into
// the binary at compile time. Both the CLI and the MCP tool ship this
// to the box and execute it server-side over SSH; no network fetch at
// runtime, so an agent can provision runners on a box with no outbound
// access to raw.githubusercontent.com.
//
// The source file at hacks/runner/install.sh stays public for ops
// engineers who prefer the manual `ssh box 'curl … | bash'` flow —
// see hacks/runner/README.md. We embed exactly the same bytes so the
// agent path and the operator path are provably the same install.
//
//go:embed install_script_payload.sh
var InstallScript []byte
