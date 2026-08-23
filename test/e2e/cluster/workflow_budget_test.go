package clustere2e

// The lane's own timing arithmetic, asserted rather than described
// (#1458).
//
// Run 12 ran for 1h40m and was cancelled at the job's timeout-minutes.
// That is the worst way for a lane to end: a cancelled job never
// reaches the "Diagnostics on failure" step or the suite's own
// dumpDiagnostics, so 100 minutes of runner time produced no evidence
// at all — indistinguishable, from the outside, from a lane that is
// merely slow.
//
// The relationship that has to hold is:
//
//	sum(step budgets) <= go timeout < job cap - setup
//
// A comment saying so relies on the next person changing a budget
// happening to read it. This does not.

import (
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const containerLaneWorkflow = "../../../.github/workflows/cluster-container-e2e.yml"

// laneSetupBudget is the runner provisioning the job does before the
// suite starts: Incus install, ZFS pool, build, Postgres image pull.
// Measured at ~10m; held at 15m so the assertion has margin of its own
// rather than tracking the fastest run ever observed.
const laneSetupBudget = 15 * time.Minute

type workflowFile struct {
	Jobs map[string]struct {
		TimeoutMinutes int               `yaml:"timeout-minutes"`
		Env            map[string]string `yaml:"env"`
	} `yaml:"jobs"`
}

func TestContainerLaneJobCapExceedsItsTestBudget(t *testing.T) {
	raw, err := os.ReadFile(containerLaneWorkflow)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}

	job, ok := wf.Jobs["container-e2e"]
	if !ok {
		t.Fatalf("no container-e2e job in %s; jobs=%v", containerLaneWorkflow, keys(wf))
	}
	if job.TimeoutMinutes == 0 {
		t.Fatal("container-e2e has no timeout-minutes, so a hung run burns a whole runner")
	}
	jobCap := time.Duration(job.TimeoutMinutes) * time.Minute

	goTimeout := mustDuration(t, job.Env, "CONTAINARIUM_E2E_GO_TIMEOUT")

	// Every per-step budget the journey can spend in sequence.
	var stepTotal time.Duration
	for _, key := range []string{
		"CONTAINARIUM_E2E_READY_TIMEOUT",
		"CONTAINARIUM_E2E_SCALEUP_TIMEOUT",
		"CONTAINARIUM_E2E_VPA_TIMEOUT",
		"CONTAINARIUM_E2E_SCALEDOWN_TIMEOUT",
		"CONTAINARIUM_E2E_DELETE_TIMEOUT",
	} {
		stepTotal += mustDuration(t, job.Env, key)
	}

	// 1. The suite must be able to spend every budget it advertises.
	if stepTotal > goTimeout {
		t.Errorf("step budgets total %v but the go timeout is %v: the suite can be killed "+
			"mid-journey while every individual step is still inside its own bound",
			stepTotal, goTimeout)
	}

	// 2. The GO TEST must be what times out, never the job. Otherwise
	//    the run ends with no diagnostics, which is what #1458 is.
	if want := goTimeout + laneSetupBudget; jobCap <= want {
		t.Errorf("job cap %v does not exceed the go timeout %v plus %v of setup: "+
			"a slow run is CANCELLED rather than failed, and a cancelled job produces "+
			"no diagnostics at all (#1458). Raise timeout-minutes to at least %v.",
			jobCap, goTimeout, laneSetupBudget, want+time.Minute)
	}
}

func mustDuration(t *testing.T, env map[string]string, key string) time.Duration {
	t.Helper()
	raw, ok := env[key]
	if !ok {
		t.Fatalf("%s is not set on the container-e2e job; the lane's budget cannot be checked", key)
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		t.Fatalf("%s=%q: %v", key, raw, err)
	}
	return d
}

func keys(wf workflowFile) []string {
	out := make([]string, 0, len(wf.Jobs))
	for k := range wf.Jobs {
		out = append(out, k)
	}
	return out
}
