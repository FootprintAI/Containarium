package containariumotel

import (
	_ "embed"
	"strings"
)

// versionEmbed is the raw contents of the VERSION file, baked in at
// build time. We use //go:embed (Phase 6 of the rollout plan) instead
// of a hand-edited const so a single file bump at release time
// updates both the package's source-of-truth value and the
// containarium.distro resource attribute stamp.
//
// Release process: when bumping pkg/version/version.go, bump this
// VERSION file to the same value. The CI workflow could enforce
// equality between the two if drift becomes a recurring issue.
//
//go:embed VERSION
var versionEmbed string

// version is the parsed distro version (whitespace-trimmed from the
// embedded VERSION file). Used as the right-hand side of the
// `containarium.distro=go/<version>` resource attribute stamp.
var version = strings.TrimSpace(versionEmbed)
