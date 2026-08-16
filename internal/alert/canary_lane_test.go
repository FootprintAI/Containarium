//go:build integration

package alert

import "testing"

// TEMPORARY — proves the lane's pipefail fix actually catches a failure in
// the FIRST go test invocation. Removed in the next commit; if you are
// reading this on main, something went wrong.
func TestLaneCanary_MustFailOnce(t *testing.T) {
	t.Fatal("deliberate failure: if the store lane is green with this present, " +
		"a red suite in the first invocation still passes the step")
}
