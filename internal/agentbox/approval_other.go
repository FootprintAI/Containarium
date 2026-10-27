//go:build !linux && !windows

package agentbox

// makeNonDumpable is a no-op off Linux; boxes are Linux.
func makeNonDumpable() error { return nil }
