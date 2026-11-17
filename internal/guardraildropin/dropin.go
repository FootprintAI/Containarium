// Package guardraildropin installs the guardrail hook into a box as a Claude
// Code managed-settings drop-in, and checks from outside the box user's
// control that it is still there and still firing (#3762;
// docs/architecture/guardrail.md, "Managed hook drop-in").
//
// This is the one place the daemon writes into a box's /etc for a coding
// agent. `code install` stays user-level (internal/coderun/engine/claude.go);
// the drop-in is root-owned on purpose, because a user-level settings file
// can be switched off with disableAllHooks and a managed one cannot.
//
// The hook handler itself (`containarium guardrail hook <event>`) is not in
// this package.
package guardraildropin

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// ManagedSettingsDir is where Claude Code reads managed settings on Linux.
	ManagedSettingsDir = "/etc/claude-code"
	// DropInDir holds managed drop-ins; every *.json in it is merged.
	DropInDir = ManagedSettingsDir + "/managed-settings.d"
	// DropInPath is the one file this package owns there.
	DropInPath = DropInDir + "/containarium-guardrail.json"
	// HookBinaryDir is root-owned, so the box user cannot swap the binary
	// without sudo. The daemon puts a pinned, statically linked copy of its
	// own CLI here: a box image carries no `containarium` binary, and a
	// drop-in that names a command that does not run blocks every tool.
	HookBinaryDir = "/usr/local/lib/containarium-guardrail"
	// HookBinaryPath is the command every hook entry runs.
	HookBinaryPath = HookBinaryDir + "/containarium"

	// DefaultHookTimeout is the per-hook timeout written into the drop-in.
	// The deadline that applies to a scan is the hook's own (2 s by
	// default, after a wait of up to 3 s for the engine); the engine
	// service's longer per-scan deadline is never reached from a hook. 15 s
	// leaves the hook room to answer for itself, with a reason, in the
	// common case. It is not a bound on the worst case: an event that scans
	// many results one after another (PostToolBatch) can exceed it, and
	// the client then kills the hook and blocks.
	DefaultHookTimeout = 15 * time.Second
	// DefaultEngineAddr is where the engine service listens in a box.
	DefaultEngineAddr = "unix:///run/containarium-engine/engine.sock"
	// DefaultMinClientVersion is the oldest Claude Code the check accepts.
	// 2.1.326 is the only version the drop-in's behaviour was tested on; the
	// documented floors of the settings it uses put the true minimum at or
	// above 2.1.299.
	DefaultMinClientVersion = "2.1.326"
)

// HookEvents are the events the drop-in registers, each as
// `containarium guardrail hook <event>`.
var HookEvents = []string{
	"SessionStart", "PreToolUse", "PostToolUse", "PostToolBatch", "UserPromptSubmit", "InstructionsLoaded",
}

// settings is the drop-in file. Only the keys this package sets: a drop-in
// is merged with any other managed policy and must not restate it. It
// deliberately has no allowManagedHooksOnly, forceLoginMethod or
// forceLoginOrgUUID.
type settings struct {
	Env   map[string]string      `json:"env"`
	Hooks map[string][]hookGroup `json:"hooks"`
}

type hookGroup struct {
	Hooks []hookCommand `json:"hooks"`
}

// hookCommand is an exec-form hook: Command is run directly with Args, no
// shell. That keeps the client process as the hook's parent, which is what
// the per-process stamp is keyed on.
type hookCommand struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	// Timeout is in seconds.
	Timeout int `json:"timeout"`
	// OnFailure "block" makes a crashed or timed-out hook stop the tool
	// call instead of letting it through. It reads no setting, which is why
	// removing the drop-in is the only break-glass.
	OnFailure string `json:"onFailure"`
}

// Render returns the drop-in's bytes. Deterministic, so the coverage check
// can compare a box's file against it byte for byte. engineAddr is passed
// to every hook as --engine; empty leaves it out, and the hook then scans
// with its in-process reference rules.
func Render(timeout time.Duration, engineAddr string) ([]byte, error) {
	if timeout < time.Second {
		return nil, fmt.Errorf("guardrail hook timeout %s is under one second", timeout)
	}
	s := settings{
		// Without this an @-mentioned file is inlined into the prompt with
		// no tool call, so no hook sees it; with it the client reads the
		// file through its Read tool.
		Env:   map[string]string{"CLAUDE_CODE_DISABLE_FILE_MENTIONS": "1"},
		Hooks: map[string][]hookGroup{},
	}
	for _, ev := range HookEvents {
		args := []string{"guardrail", "hook", ev}
		if engineAddr != "" {
			args = append(args, "--engine", engineAddr)
		}
		s.Hooks[ev] = []hookGroup{{Hooks: []hookCommand{{
			Type:      "command",
			Command:   HookBinaryPath,
			Args:      args,
			Timeout:   int(timeout / time.Second),
			OnFailure: "block",
		}}}}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
