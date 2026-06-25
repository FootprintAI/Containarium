package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/sshkey"
)

// connectReadyTimeout bounds how long connect waits for a freshly-created box
// to finish coming up, and connectPollInterval is the gap between re-checks.
// An agent commonly creates a box then immediately connects, racing the
// box's bring-up — waiting absorbs that race instead of erroring.
// vars (not consts) so tests can shrink them.
var (
	connectReadyTimeout = 90 * time.Second
	connectPollInterval = 3 * time.Second
)

// handleConnect is the agent-native half of `containarium connect` — the
// thin MCP wrapper over the same connectcore resolve+authorize core the
// CLI verb uses (the "one Go func, two surfaces" pattern, per CLAUDE.md).
//
// An MCP call is request/response with no PTY, so only the two
// non-interactive modes are surfaced:
//
//   - config mode (no `exec` arg): resolve the box, authorize the managed
//     key, and return the ready `ssh <user>@<host>` invocation. The
//     human's terminal connects.
//   - exec mode (`exec` arg): run one command over SSH and return its
//     stdout / stderr / exit_code — operate the box without a TTY.
//
// Interactive (PTY) stays CLI-only.
func handleConnect(client API, args map[string]interface{}) (string, error) {
	box := strings.TrimSpace(getStringArg(args, "box", ""))
	if box == "" {
		return "", fmt.Errorf("`box` is required")
	}
	execCmd := getStringArg(args, "exec", "")
	userOverride := getStringArg(args, "user", "")
	hostOverride := getStringArg(args, "host", "")

	target, err := mcpWaitConnectable(client, box, userOverride, hostOverride)
	if err != nil {
		return "", err
	}

	// Reuse (or generate once) the managed key the `ssh setup` flow uses,
	// so the operator never hand-manages a key. The MCP server runs on the
	// operator's machine, so this is the same key material the CLI sees.
	pubPath, pub, _, err := sshkey.LocateOrGenerate(sshkey.LocateOpts{})
	if err != nil {
		return "", fmt.Errorf("locate or generate managed key: %w", err)
	}
	privPath := strings.TrimSuffix(pubPath, ".pub")

	if err := mcpAuthorizeKey(client, box, pub); err != nil {
		return "", fmt.Errorf("authorize key on %q: %w", box, err)
	}

	// Tier 2 — stateful tmux session on the box. State (cd, exports,
	// background jobs) persists across calls with the same session name.
	if session := strings.TrimSpace(getStringArg(args, "session", "")); session != "" {
		if err := connectcore.ValidateSessionName(session); err != nil {
			return "", err
		}
		if execCmd == "" {
			// No terminal in an MCP call — hand off the attach command.
			attach := "ssh " + strings.Join(connectcore.BuildAttachArgs(target, privPath, session), " ")
			return fmt.Sprintf(
				"Session %q on %s is ready. Pass `exec` to run a command inside it, or attach a terminal:\n\n    %s\n",
				session, box, attach), nil
		}
		return runMCPSessionExec(target, privPath, session, execCmd)
	}

	if execCmd == "" {
		// Config mode: hand the ready invocation back for the human to run.
		sshArgs := connectcore.BuildSSHArgs(target, privPath, execCmd)
		fp, _ := sshkey.Fingerprint(pub)
		return fmt.Sprintf(
			"✓ %s is ready — key %s authorized.\nRun this in your terminal:\n\n    ssh %s\n",
			box, fp, strings.Join(sshArgs, " ")), nil
	}
	// Exec mode: run the one-shot command in-process (pure-Go SSH, no system
	// ssh binary) and return its output + exit code.
	return runMCPSSHExec(target, privPath, execCmd)
}

// mcpWaitConnectable resolves a box to an SSH target, waiting out the
// create→running race: an agent often creates a box then immediately calls
// connect, so the box is still CREATING/PROVISIONING (or RUNNING but without
// an IP yet). Rather than failing with the misleading "start it first" — you
// cannot start a box that is already coming up — it polls until the box is
// RUNNING with a usable target, or the deadline passes. A genuinely stopped
// box returns the start-it-first guidance immediately, since waiting on it
// would never succeed.
func mcpWaitConnectable(client API, box, userOverride, hostOverride string) (connectcore.Target, error) {
	deadline := time.Now().Add(connectReadyTimeout)
	for {
		c, err := mcpGetContainer(client, box)
		if err != nil {
			return connectcore.Target{}, err
		}
		switch {
		case connectcore.IsRunning(c.State):
			target, terr := connectcore.BuildTarget(c, userOverride, hostOverride, 22)
			if terr == nil {
				return target, nil
			}
			// Running but no IP/host assigned yet — keep waiting briefly.
			if time.Now().After(deadline) {
				return connectcore.Target{}, terr
			}
		case connectcore.IsTransientState(c.State):
			if time.Now().After(deadline) {
				return connectcore.Target{}, fmt.Errorf(
					"box %q is still %s after %s — it may need longer to come up; try again shortly",
					box, connectcore.PrettyState(c.State), connectReadyTimeout)
			}
		default:
			// stopped / frozen / error — waiting would not help.
			return connectcore.Target{}, fmt.Errorf("box %q is %s, not running — start it first", box, connectcore.PrettyState(c.State))
		}
		time.Sleep(connectPollInterval)
	}
}

// mcpGetContainer GETs the box over the MCP client's daemon connection and
// decodes it into the shared connectcore DTO. doRequest folds the status
// into its error string; we detect 404 there to give a clean "not found".
func mcpGetContainer(client API, box string) (*connectcore.Container, error) {
	body, err := client.doRequest("GET", "/v1/containers/"+url.PathEscape(box), nil)
	if err != nil {
		if strings.Contains(err.Error(), "status 404") {
			return nil, fmt.Errorf("box %q not found", box)
		}
		return nil, err
	}
	var resp connectcore.GetContainerResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode container: %w", err)
	}
	return &resp.Container, nil
}

func mcpAuthorizeKey(client API, box, pub string) error {
	_, err := client.doRequest("POST",
		"/v1/containers/"+url.PathEscape(box)+"/ssh-keys",
		connectcore.AuthorizeKeyRequest{SshPublicKey: pub})
	return err
}
