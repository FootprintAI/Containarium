//go:build windows

package audit

import "os/exec"

// bindToProcessGroup is a no-op on windows; the daemon never ships there and
// cmd.WaitDelay still bounds the call.
func bindToProcessGroup(*exec.Cmd) {}
