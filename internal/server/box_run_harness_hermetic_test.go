//go:build !containarium_client

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// slowToolShims puts executables named like the package managers and runtimes
// the toolchain probe runs (#2954) at the FRONT of PATH, each sleeping far longer
// than the probe's own 3s timeout. A CI runner has real ones, and the slow ones
// (npm, yarn, pnpm shims, a cold JVM) are exactly what held a run open (#2973).
func slowToolShims(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"yarn", "pnpm", "npm", "java", "node"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nsleep 30\necho 1.0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// #2973: the box-run tests must not depend on which tools the machine running
// them has installed. The run wrapper's end-of-run probe runs every allowlisted
// tool it finds, and the run is not reported finished until the probe returns,
// so on a host with slow tools every test waiting on EXITED took 3s or more and
// failed intermittently against its own 3s bound. With the harness hermetic, a
// run whose fake engine exits in 50ms reaches EXITED in well under a second,
// whatever is installed.
func TestBoxRunHarness_RunFinishesQuicklyWhateverToolsTheHostHas(t *testing.T) {
	slowToolShims(t)
	u := newFakeBoxUser(t, 0, 50*time.Millisecond)
	s, _, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hello"}); err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	start := time.Now()
	waitForOutcome(t, s, "alice", "code", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 2*time.Second)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("run took %s to finish: the host's tools are leaking into the test", took)
	}
}
