// Package toolaccess is the one mapping between the BoxToolAccess proto enum
// and the string stored in the user.containarium.tool_access Incus config key
// (#2944). The daemon (writing and reading the key) and the client (showing
// it) both use it, so the two cannot drift.
package toolaccess

import (
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// RunUser is the unprivileged OS user platform-started runs execute as on a box
// with a recorded tool-access level (#2944, slice 1b). One name shared by the
// daemon's run path and the gateway's terminal route (#3275), so the sign-in
// terminal can never open as a different user than the one the run is refused on.
const RunUser = "ctn-run"

// ConfigValue maps the enum to its stored value. ok is false for UNSPECIFIED
// (which means "clear the key") and for any value this build does not know.
func ConfigValue(a pb.BoxToolAccess) (value string, ok bool) {
	switch a {
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE:
		return incus.ToolAccessNone, true
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS:
		return incus.ToolAccessBuildTools, true
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO:
		return incus.ToolAccessFullSudo, true
	}
	return "", false
}

// FromConfig maps a stored value to the enum. An absent or unrecognised value
// is UNSPECIFIED, never a level, so a typo set by hand with `incus config set`
// cannot grant anything.
func FromConfig(v string) pb.BoxToolAccess {
	switch v {
	case incus.ToolAccessNone:
		return pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE
	case incus.ToolAccessBuildTools:
		return pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS
	case incus.ToolAccessFullSudo:
		return pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO
	}
	return pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED
}
