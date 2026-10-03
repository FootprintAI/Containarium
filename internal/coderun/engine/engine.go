// Package engine makes the coding agent and its credential source typed
// choices in `containarium code` (#1727), instead of the Claude-only,
// tenant-secret-only path #1673/#1674 shipped.
//
// The split follows what is actually engine-specific. The resumable reader —
// `code run`/`attach`/`status`/`stop`, internal/coderun — only ever sees bytes
// and byte offsets, so it is engine-agnostic and is NOT touched here. Three
// things do differ per engine, and they are this package's whole surface:
//
//   - InstallScript: how the binary lands on the box.
//   - VerifyScript: how the install proves the box can actually reach a model.
//   - RunCommand: the command process_start spawns.
//
// Credentials are the second axis. A `secret` source is the shipped behaviour
// (a tenant secret reaching the run through the box's own shell environment);
// a `gateway` source is #1726's scoped, short-lived gateway token, so the box
// holds no provider key at all. The axes are independent — an engine is
// constructed WITH a credential source (For) rather than being handed one per
// call, which is what keeps RunCommand's signature down to the three arguments
// that vary per run.
//
// Design: docs/architecture/workspace-own-inference-key.md (cloud repo),
// component 3 and contract C4.
package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/footprintai/containarium/internal/coderun"
)

// Name identifies a coding engine. A string type rather than a bare string so
// a mistyped literal is a compile error at every call site, and so the JSON
// record in code.json has one vocabulary (CLAUDE.md: use the type system).
type Name string

const (
	// NameClaude is Claude Code, the engine `containarium code` has always
	// installed. It is the DEFAULT for --engine, which is what makes #1727 a
	// no-behaviour-change addition for existing users.
	NameClaude Name = "claude"
	// NamePi is pi (https://pi.dev, @earendil-works/pi-coding-agent), a
	// local-first agent that runs inside the box. See docs/integrations/pi.md.
	NamePi Name = "pi"
)

// DefaultName is what --engine resolves to when the flag is absent.
//
// This constant is load-bearing, not a convenience: every box installed before
// #1727 has no engine recorded, and every user who never passes --engine must
// keep getting exactly Claude Code. Changing it is a breaking change to a
// shipped command.
const DefaultName = NameClaude

// GatewayTokenEnvVar and GatewayURLEnvVar are the two variables a box's
// gateway.env exports. They are NOT redefined here — they are the contract
// `containarium gateway mint --env` already prints (internal/cmd/gateway.go)
// and internal/server/agent_gateway.go already writes, and a box seeded by
// either path has to be readable by the other.
const (
	// #nosec G101 -- the NAME of the environment variable a token is read from,
	// not a credential value. Nothing in this package holds a token: the
	// rendered models.json carries "$CONTAINARIUM_GATEWAY_TOKEN" and the value
	// only ever exists in the box's 0600 gateway.env. Same annotation the
	// removed CLAUDE_CODE_OAUTH_TOKEN constant carried for the same reason.
	GatewayTokenEnvVar = "CONTAINARIUM_GATEWAY_TOKEN"
	GatewayURLEnvVar   = "CONTAINARIUM_MODEL_GATEWAY_URL"
)

// Options are the per-box choices an engine is bound to, as recorded in
// code.json. They come from `code install`'s flags and are read back by `code
// run` — never re-asked.
type Options struct {
	// Credential is how this box's runs get a model credential. Required.
	Credential CredentialSource
	// Model is the model id to pin a run to, empty for "the engine's own
	// default". For a gateway credential it is also the token's
	// allowed_models ceiling, which is why it is worth recording.
	Model string
}

// InstallOptions are the inputs to InstallScript that vary per install rather
// than per box.
type InstallOptions struct {
	// Version pins the engine's own version. Empty means "whatever the
	// engine's installer considers current" — acceptable for Claude Code,
	// whose installer takes a version argument, and deliberately NOT the
	// default for pi (see pi.go).
	Version string
	// ModelsJSON is pi's rendered ~/.pi/agent/models.json. Ignored by engines
	// that have no such file.
	ModelsJSON string
}

// Engine is one coding agent's install/verify/run behaviour.
//
// Every method returns a POSIX shell script or command rather than executing
// anything. That keeps the whole surface pure and table-testable: the exact
// bytes that will reach `/bin/sh -c` on someone's box are comparable in a unit
// test, which is the only way the AC's "shell quoting pinned" is provable.
type Engine interface {
	// Name is this engine's own identifier, as recorded in code.json.
	Name() Name
	// Credential is the source this engine was constructed with.
	Credential() CredentialSource
	// GatewayEnvPath is the 0600 file `code run` writes the per-run gateway
	// token to before process_start, and that RunCommand sources. Engines keep
	// their own config directories, so this is per-engine.
	GatewayEnvPath() string
	// InstallScript lands the engine on the box.
	InstallScript(InstallOptions) string
	// VerifyScript proves the install can reach a model. It runs after
	// InstallScript and, for a gateway credential, after a short-lived token
	// has been written to GatewayEnvPath.
	VerifyScript() string
	// RunCommand renders the command process_start spawns for one run.
	//
	// continueSession resumes the engine's most recent session in the run's
	// working directory rather than starting a fresh one (`--continue` on the
	// CLI; `-c` for pi). sessionID, when non-empty, resumes that SPECIFIC
	// session instead (`claude --resume <id>`; `pi --session <id>`,
	// docs/integrations/pi.md) and takes priority over continueSession —
	// callers validate the two are mutually exclusive before calling this
	// (#2193), so RunCommand itself never has to choose between them.
	RunCommand(prompt string, streamJSON, continueSession bool, sessionID string) string
}

// For returns the engine named n, bound to opts.
func For(n Name, opts Options) (Engine, error) {
	if opts.Credential == nil {
		return nil, fmt.Errorf("engine %q needs a credential source", n)
	}
	switch n {
	case NameClaude:
		return claudeEngine{opts: opts}, nil
	case NamePi:
		return piEngine{opts: opts}, nil
	default:
		return nil, fmt.Errorf("unknown engine %q (one of: %s)", n, strings.Join(Names(), ", "))
	}
}

// Names lists every engine --engine accepts, for flag help and error messages.
func Names() []string {
	out := []string{string(NameClaude), string(NamePi)}
	sort.Strings(out)
	return out
}

// ParseName resolves an --engine flag value.
//
// An unrecognised value is an error listing the valid ones — never a silent
// fall back to the default. Running the wrong agent on someone's box because
// they typed "cluade" is not a recoverable mistake.
func ParseName(s string) (Name, error) {
	switch n := Name(strings.ToLower(strings.TrimSpace(s))); n {
	case NameClaude, NamePi:
		return n, nil
	default:
		return "", fmt.Errorf("unknown engine %q (one of: %s)", s, strings.Join(Names(), ", "))
	}
}

// sourceEnvPrefix is the shell prefix that loads an env file into a run's
// environment, if it exists.
//
// It mirrors internal/server/agent_gateway.go's sourceGatewayEnvPrefix
// character for character, deliberately: a box may be seeded by the daemon
// (skill boxes) or by this CLI (`code install`), and a run must not care which.
// The `[ -f ... ] &&` guard is why an absent file is a run with no credential
// rather than a shell error the user has to decode.
func sourceEnvPrefix(quotedPath string) string {
	return "set -a; [ -f " + quotedPath + " ] && . " + quotedPath + "; set +a; "
}

// shellQuoteSingle is coderun's quoter, re-exported inside this package so
// every command built here uses the ONE implementation the injection tests
// already cover. Duplicating it is how a second, subtly weaker quoter appears.
func shellQuoteSingle(s string) string { return coderun.ShellQuoteSingle(s) }
