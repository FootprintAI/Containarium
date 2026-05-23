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
