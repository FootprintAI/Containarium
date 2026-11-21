package incusenv

import (
	"errors"
	"strings"
	"testing"
)

// fakeHost records the commands a Teardown issues and answers from a script,
// standing in for the incus and zfs CLIs.
type fakeHost struct {
	calls   []string
	failing map[string]string // command prefix -> output; the call fails
	gone    bool              // `zfs list` reports the dataset absent
	// poolDeleteDestroysDataset models Incus: deleting a pool created on a
	// dataset removes that dataset as well.
	poolDeleteDestroysDataset bool
}

func (f *fakeHost) run(name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	for prefix, out := range f.failing {
		if strings.HasPrefix(cmd, prefix) {
			return []byte(out), errors.New("exit status 1")
		}
	}
	if strings.HasPrefix(cmd, "incus storage delete") && f.poolDeleteDestroysDataset {
		f.gone = true
	}
	if strings.HasPrefix(cmd, "zfs list") && f.gone {
		return []byte("dataset does not exist"), errors.New("exit status 1")
	}
	return nil, nil
}

func TestTeardownDeletesInstancesBeforeTheirDataset(t *testing.T) {
	f := &fakeHost{gone: true}
	errs := Teardown{Instances: []string{"a", "b"}, Pool: "p", Dataset: "ds"}.Run(f.run)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := []string{
		"incus delete --force a",
		"incus delete --force b",
		"incus storage delete p",
		"zfs destroy -r ds",
		"zfs list -H -o name ds",
	}
	if strings.Join(f.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", f.calls, want)
	}
}

// An instance that cannot be deleted must keep its dataset: destroying it
// out from under a registered instance is what broke the next package's
// default-profile update.
func TestTeardownKeepsTheDatasetWhenAnInstanceSurvives(t *testing.T) {
	f := &fakeHost{failing: map[string]string{"incus delete --force a": "instance is busy"}}
	errs := Teardown{Instances: []string{"a"}, Pool: "p", Dataset: "ds"}.Run(f.run)
	if len(errs) == 0 {
		t.Fatal("a surviving instance must be reported")
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "zfs destroy") {
			t.Fatalf("dataset destroyed while instance a survives: %q", f.calls)
		}
	}
}

func TestTeardownToleratesAnInstanceThatWasNeverCreated(t *testing.T) {
	f := &fakeHost{gone: true, failing: map[string]string{"incus delete --force a": "Error: Instance not found"}}
	if errs := (Teardown{Instances: []string{"a"}, Dataset: "ds"}).Run(f.run); len(errs) != 0 {
		t.Fatalf("not-found is fine, got %v", errs)
	}
}

func TestTeardownFailsWhenTheDatasetIsStillThere(t *testing.T) {
	f := &fakeHost{gone: false}
	errs := Teardown{Instances: []string{"a"}, Dataset: "ds"}.Run(f.run)
	if len(errs) == 0 {
		t.Fatal("a dataset that survives the destroy must be reported")
	}
}

func TestTeardownReportsAFailedDestroy(t *testing.T) {
	f := &fakeHost{gone: true, failing: map[string]string{"zfs destroy": "dataset is busy"}}
	if errs := (Teardown{Dataset: "ds"}).Run(f.run); len(errs) == 0 {
		t.Fatal("a failed zfs destroy must be reported")
	}
}

// The pool delete removes the dataset, so the destroy that follows finds it
// absent. That is the state the teardown is meant to reach, not an error (the
// box-backup cleanup failed on exactly this in the real-Incus lane).
func TestTeardownAcceptsADatasetThePoolDeleteAlreadyRemoved(t *testing.T) {
	f := &fakeHost{poolDeleteDestroysDataset: true, failing: map[string]string{"zfs destroy": "cannot open 'ds': dataset does not exist"}}
	if errs := (Teardown{Pool: "p", Dataset: "ds"}).Run(f.run); len(errs) != 0 {
		t.Fatalf("dataset already removed by the pool delete must not be an error: %v", errs)
	}
}
