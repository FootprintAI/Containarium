//go:build windows

package sshsession

import "os"

// inodeOf is unavailable on windows; the shipper then falls back to
// size-based truncation detection only (the sentinel is linux-only anyway).
func inodeOf(os.FileInfo) (uint64, bool) { return 0, false }
