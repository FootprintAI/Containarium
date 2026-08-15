// Package incusenv asserts that a real, usable Incus is present before an
// Incus-backed integration test runs, and decides what to do when one is not
// (#1332).
//
// The decision is the whole point of the package. On a developer's laptop or
// a container dev box there is legitimately no Incus, and skipping is right.
// In the CI lane that exists to *demonstrate* the daemon's create path, a
// skip is the failure mode: the job reports green having proven nothing,
// which is exactly what let #1195 merge on a check that could not fail
// (#1234). So the lane sets CONTAINARIUM_REQUIRE_INCUS and the same missing
// environment becomes a hard failure naming the step that was missing.
//
// This file carries no build tag on purpose: the switch itself is testable —
// and provably able to fail — in the ordinary unit suite, without an Incus
// anywhere. The code that touches a real Incus lives behind the `incus` tag.
package incusenv

import (
	"os"
	"strings"
)

// RequireEnv is the environment variable that turns "no usable Incus here"
// from a skip into a failure. Set it in any lane whose job is to prove the
// Incus path actually runs.
const RequireEnv = "CONTAINARIUM_REQUIRE_INCUS"

// Disposition is what a test should do when the Incus environment turns out
// to be unusable.
type Disposition int

const (
	// Skip leaves the test unrun — the honest outcome on a machine that was
	// never expected to have Incus.
	Skip Disposition = iota

	// Fail treats the missing environment as the defect under test.
	Fail
)

func (d Disposition) String() string {
	if d == Fail {
		return "fail"
	}
	return "skip"
}

// DispositionFor maps the value of RequireEnv onto what an unusable
// environment means.
//
// Only an affirmative value opts in. "0" and "false" are read as the operator
// saying no, not as "the variable is set, so require it" — a lane that
// disables the requirement by setting it to 0 must not get the opposite of
// what it asked for.
func DispositionFor(value string) Disposition {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return Fail
	default:
		return Skip
	}
}

// BoxImage is the image the lane's tests create containers from.
//
// Overridable so CI can point every test at an image already pulled into the
// runner's local store. Without that, each test fetches
// `images:ubuntu/24.04` from images.linuxcontainers.org at run time — five or
// more fetches per run against a third-party mirror, and when that mirror
// hiccups every PR touching the lane fails at once with "The requested image
// couldn't be found", which reads as a code failure (#1375).
//
// Defaults to the public alias so a developer's laptop needs no setup.
func BoxImage() string {
	if img := os.Getenv("CONTAINARIUM_LANE_IMAGE"); img != "" {
		return img
	}
	return "images:ubuntu/24.04"
}
