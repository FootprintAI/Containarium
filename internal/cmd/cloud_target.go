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
