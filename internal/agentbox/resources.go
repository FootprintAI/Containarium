//go:build !windows

package agentbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ciContextResourceURI is the MCP URI agents read to discover what (if
// anything) the box is being used for. Stable across the box's lifetime;
// agents are expected to fetch it once on connect.
const ciContextResourceURI = "containarium://ci-context"

// ciContextPathEnv lets tests (and unusual deployments) point the resource
// at a non-default path without recompiling. The default lives at the
// well-known `/workspace/.containarium/` location that the
// containarium-run GitHub Action writes to.
const ciContextPathEnv = "CONTAINARIUM_CI_CONTEXT_PATH"

// defaultCIContextPath is the canonical on-box location for the CI context
// JSON file. Matches what the FootprintAI/containarium-run Action writes
// when it keeps a failed CI run's box alive for debugging.
const defaultCIContextPath = "/workspace/.containarium/ci-context.json"

// ciContextAbsentBody is what we return when no ci-context.json exists on
// the box. We deliberately return valid JSON instead of an error so that
// agents can always parse the body — `available: false` is the documented
// "this box isn't a CI box" sentinel.
const ciContextAbsentBody = `{"schema_version":"1.0","platform":null,"available":false}`

// ciContextPath returns the file path the ci-context resource reads from,
// honoring the env-var override when set so tests can point it at a
// tempdir without monkey-patching globals.
func ciContextPath() string {
	if p := os.Getenv(ciContextPathEnv); p != "" {
		return p
	}
	return defaultCIContextPath
}

// registerCIContextResource wires the ci-context MCP resource onto the
// given server. Mirrors the registerFoo pattern that tools follow in this
// package so resources are discoverable alongside them.
func registerCIContextResource(s *server.MCPServer) {
	resource := mcp.NewResource(
		ciContextResourceURI,
		"CI context",
		mcp.WithResourceDescription(
			"JSON metadata about the current CI run (PR number, commit SHA, "+
				"failing test, etc.) — populated by FootprintAI/containarium-run. "+
				"Empty if the box is not being used for CI.",
		),
		mcp.WithMIMEType("application/json"),
	)
	s.AddResource(resource, handleCIContextRead)
}

// handleCIContextRead is the resource handler. The body is opaque
// pass-through: we read whatever bytes the writer produced and hand them
// back unparsed. If the file is missing we return a valid-JSON stub so
// callers never have to special-case errors — an absent file is normal
// (the box might not be a CI box).
func handleCIContextRead(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	path := ciContextPath()

	// #nosec G304 -- path comes from a compile-time constant or an
	// operator-set env var, never from MCP request input.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      ciContextResourceURI,
					MIMEType: "application/json",
					Text:     ciContextAbsentBody,
				},
			}, nil
		}
		return nil, fmt.Errorf("read ci-context file %s: %w", path, err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      ciContextResourceURI,
			MIMEType: "application/json",
			Text:     string(data),
		},
	}, nil
}

// ciPromptResourceURI is the MCP URI for the static "how to debug a
// failing CI run" playbook. Paired with ciContextResourceURI: ci-context
// gives the agent the *data* (which PR, which test), ci-prompt gives it
// the *behavior* (how to investigate, what not to do).
const ciPromptResourceURI = "containarium://ci-prompt"

// ciPromptBody is the opinionated playbook returned by the ci-prompt
// resource. Baked into the binary as a constant so the resource is
// always available with zero filesystem dependencies — the prompt is
// the same for every Containarium-hosted CI debug session in v0.
//
// Keep this prescriptive. The whole point is to give agents clear
// behavior guidance rather than hedged suggestions.
const ciPromptBody = `# Debugging a failing CI run in Containarium

You are connected to a Containarium box that was kept alive after a CI
test failure. Your job is to diagnose and propose a fix — not just
describe the problem.

## What to read first

1. **` + "`containarium://ci-context`" + `** — JSON with the PR number, commit
   SHA, branch, failing test name, and last ~50 lines of test output.
   Read this before anything else; it tells you what to focus on.
2. **` + "`/workspace/`" + `** — the repo's source code, checked out at the
   failing commit. The path is also in ` + "`ci-context.workspace_path`" + `.

## How to work

- Use ` + "`shell_exec`" + ` to reproduce the failure. The test command lives in
  the project's ` + "`.github/containarium.yml`" + ` under the ` + "`test:`" + ` key.
- Inspect the failing test's source and recent commits on the file
  (` + "`git log -p -- <path>`" + `). The bug is usually in code touched by this
  PR, not in stable code.
- Make minimal, scoped fixes. Don't refactor unrelated code, don't
  bump dependencies, don't reformat files you aren't touching.
- Re-run the failing test after each change. Iterate until it passes.

## How to report

When you have a fix:

1. Show the diff (` + "`git diff`" + ` or per-file patches).
2. Explain in one sentence what the root cause was.
3. Note any tests you didn't run (e.g. flaky tests skipped, integration
   tests requiring external services). The operator who reviews your
   proposal needs to know what's still untested.

## What NOT to do

- **Don't push commits or open PRs from this box.** You don't have
  repo write credentials, and even if you did, code changes should
  go through the operator's review on their machine.
- **Don't modify ` + "`/workspace/.containarium/`" + `.** That directory belongs
  to the CI tooling and shouldn't be edited.
- **Don't run destructive commands** (` + "`rm -rf`" + `, ` + "`git reset --hard`" + `,
  etc.) without first explaining why.

## When you're stuck

If reproduction or diagnosis stalls, write a short summary of what
you tried and what you observed, then stop. The operator can pick up
the thread.
`

// registerCIPromptResource wires the ci-prompt MCP resource onto the
// given server. Mirrors registerCIContextResource, with a static body
// instead of a file read — the prompt is the same on every box.
func registerCIPromptResource(s *server.MCPServer) {
	resource := mcp.NewResource(
		ciPromptResourceURI,
		"CI debug playbook",
		mcp.WithResourceDescription(
			"An opinionated prompt for agents debugging a failing CI run "+
				"inside this box. Read alongside containarium://ci-context.",
		),
		mcp.WithMIMEType("text/markdown"),
	)
	s.AddResource(resource, handleCIPromptRead)
}

// handleCIPromptRead returns the static playbook body. No filesystem
// reads, no error path — the body is a compile-time constant.
func handleCIPromptRead(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      ciPromptResourceURI,
			MIMEType: "text/markdown",
			Text:     ciPromptBody,
		},
	}, nil
}
