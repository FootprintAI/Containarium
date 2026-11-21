package incusenv

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Runner executes one command and returns its combined output. It is the
// seam that lets the teardown order be tested without Incus or ZFS.
type Runner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput() // #nosec G204 -- test-controlled names
}

// Teardown removes what a test built on a dedicated ZFS dataset: instances,
// then the storage pool, then the dataset, in that order.
//
// The order is the point (#3738). An instance still registered in Incus
// whose dataset is gone makes every later default-profile update fail
// ("zfs set ... dataset does not exist"), so the dataset is only destroyed
// once every instance on it is confirmed deleted, and is then checked to be
// gone rather than assumed.
type Teardown struct {
	Instances []string
	Pool      string // optional
	Dataset   string
}

// Run executes the teardown and returns every problem it found; nil means
// the instances, pool and dataset are all gone.
func (td Teardown) Run(run Runner) []error {
	var errs []error
	for _, name := range td.Instances {
		if out, err := run("incus", "delete", "--force", name); err != nil && !strings.Contains(string(out), "not found") {
			errs = append(errs, fmt.Errorf("instance %s survives teardown: %w\n%s", name, err, out))
		}
	}
	if len(errs) > 0 {
		// Leave the dataset in place so the surviving instance is not
		// orphaned; the failure above is what the test reports.
		return errs
	}
	if td.Pool != "" {
		if out, err := run("incus", "storage", "delete", td.Pool); err != nil {
			errs = append(errs, fmt.Errorf("storage pool %s not deleted: %w\n%s", td.Pool, err, out))
		}
	}
	if out, err := run("zfs", "destroy", "-r", td.Dataset); err != nil {
		errs = append(errs, fmt.Errorf("zfs destroy -r %s: %w\n%s", td.Dataset, err, out))
	}
	if _, err := run("zfs", "list", "-H", "-o", "name", td.Dataset); err == nil {
		errs = append(errs, fmt.Errorf("dataset %s still exists after teardown", td.Dataset))
	}
	return errs
}

// RunTeardown runs td against the real incus and zfs CLIs and fails t for
// every problem. Register it with t.Cleanup.
func RunTeardown(t *testing.T, td Teardown) {
	t.Helper()
	for _, err := range td.Run(execRunner) {
		t.Errorf("cleanup: %v", err)
	}
}
