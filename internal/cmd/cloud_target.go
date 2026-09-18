package cmd

import (
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/credentials"
)

// isCloudTarget reports whether the effective (server, token) points at the
// hosted control plane, where host-level operations — system info, per-box
// debug, control-plane upgrade / release checks — are not available per
// tenant. Host-level CLI commands call this to refuse CLIENT-SIDE with a clear
// message instead of round-tripping to an opaque 404.
//
// Two signals, mirroring the MCP backend classifier (#456):
//   - the token's shape — a `ctnr_` API key is a one-way cloud signal; and
//   - the cached AccessModel for the server (AccessModelToken == cloud), which
//     catches a cloud login whose token isn't prefix-identifiable.
func isCloudTarget(server, token string) bool {
	if credentials.IsCloudToken(token) {
		return true
	}
	return accessModelFor(server) == credentials.AccessModelToken
}

// errUnsupportedOnCloud is the clear, actionable error a host-level command
// returns when pointed at the hosted control plane. `alt` names what to use
// instead (may be empty).
func errUnsupportedOnCloud(op, alt string) error {
	msg := fmt.Sprintf("%s is a host-level operation and is not available on the hosted control plane", op)
	if alt != "" {
		msg += "; " + alt
	}
	return errors.New(msg)
}

// errRequiresCloud is errUnsupportedOnCloud's mirror image (#1607): a
// control-plane-only command (org settings, region discovery — anything
// scoped to an organization) refusing cleanly against a standalone daemon,
// which has no organizations, instead of round-tripping to a 404 the daemon
// never defines.
func errRequiresCloud(op string) error {
	return fmt.Errorf("%s requires a hosted control plane and is not available against a standalone daemon", op)
}

// resolveOrgID returns the organization id stored for server in the
// credentials file (the same one `containarium whoami` reports), or "" if
// there is none — no session, an unrecognized server, or a daemon target
// (which never has one). Mirrors resolveAuthToken's shape/failure posture:
// best-effort, never itself an error, so a caller with nothing to resolve
// gets an empty string and produces its own actionable message.
func resolveOrgID(server string) string {
	path, err := credentials.DefaultPath()
	if err != nil {
		return ""
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return ""
	}
	creds, ok := cf.Get(server)
	if !ok {
		return ""
	}
	return creds.OrgID
}
