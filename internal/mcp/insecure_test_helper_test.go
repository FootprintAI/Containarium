package mcp

import "os"

// All tests in this package use `httptest.NewServer`, which only
// speaks http://. The Phase 2.2 hardening refuses http:// baseURLs
// by default (audit C-HIGH-1). Setting the escape-hatch env var
// here keeps unit tests fast and offline; production deployments
// never touch this code path.
func init() {
	os.Setenv("CONTAINARIUM_MCP_ALLOW_INSECURE", "true")
}
