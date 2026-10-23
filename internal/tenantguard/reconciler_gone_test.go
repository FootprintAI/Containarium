package tenantguard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// The error a guard pass got on a real host when a failed create's rollback
// deleted the instance between the pass listing it and attaching its NIC
// (#2850).
var errDatasetGone = errors.New("ensure nic device eth0 on bob-container (operation failed): " +
	"Failed to write backup file: Failed to run: zfs set mountpoint=legacy canmount=noauto " +
	"tank/containers/bob-container: exit status 1 (cannot open " +
	"'tank/containers/bob-container': dataset does not exist)")

func fastGoneChecks(t *testing.T) {
	t.Helper()
	prevB, prevN := goneBackoff, goneChecks
	goneBackoff, goneChecks = time.Millisecond, 3
	t.Cleanup(func() { goneBackoff, goneChecks = prevB, prevN })
}

// removeFromHost makes the named instance vanish from ListContainers, the way
// a finished rollback does.
func removeFromHost(f *fakeBackend, name string) func(string) {
	return func(string) {
		kept := f.containers[:0:0]
		for _, c := range f.containers {
			if c.Name != name {
				kept = append(kept, c)
			}
		}
		f.containers = kept
	}
}

// An instance that is removed while the pass is attaching NICs is not a
// failure of the pass: the other boxes are still guarded and the pass
// reports success, with nothing recorded against the vanished box.
func TestReconcile_InstanceRemovedMidPassIsSkippedNotFailed(t *testing.T) {
	fastGoneChecks(t)
	f := twoTenantHost()
	f.ensureErrs = map[string]error{"bob-container": errDatasetGone}
	f.onEnsureErr = removeFromHost(f, "bob-container")

	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("a box deleted mid-pass failed the whole pass: %v", err)
	}
	st := r.Status()
	if st.LastError != "" {
		t.Errorf("LastError = %q, want none", st.LastError)
	}
	var attached int
	for _, e := range st.Entries {
		if e.Container == "bob-container" {
			t.Errorf("the removed box is still reported: %+v", e)
		}
		if e.Attached {
			attached++
		}
	}
	if attached != 3 {
		t.Errorf("attached = %d, want the 3 boxes that remain", attached)
	}
}

// A dataset error for an instance that is STILL listed once the re-checks run
// out is a real fault and is reported, never hidden as a race.
func TestReconcile_DatasetErrorOnAnInstanceThatStaysIsStillAnError(t *testing.T) {
	fastGoneChecks(t)
	f := twoTenantHost()
	f.ensureErrs = map[string]error{"bob-container": errDatasetGone}

	r := NewReconciler(f, enforceCfg())
	err := r.ReconcileOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dataset does not exist") {
		t.Fatalf("err = %v, want the dataset error reported", err)
	}
	var found bool
	for _, e := range r.Status().Entries {
		if e.Container == "bob-container" {
			found = true
			if e.Attached || e.LastError == "" {
				t.Errorf("entry should carry the error: %+v", e)
			}
		}
	}
	if !found {
		t.Error("the failing box is missing from the status")
	}
}

// The rollback may finish a moment after the error: the re-check gives it a
// few tries before concluding the instance is not going away.
func TestReconcile_InstanceThatDisappearsOnALaterRecheckIsSkipped(t *testing.T) {
	fastGoneChecks(t)
	f := twoTenantHost()
	f.ensureErrs = map[string]error{"bob-container": errDatasetGone}
	listCalls := 0
	f.afterList = func() {
		listCalls++
		if listCalls == 3 { // gather, then the 1st re-check still sees it, the 2nd does not
			removeFromHost(f, "bob-container")("")
		}
	}

	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("err = %v, want the box skipped once it was gone", err)
	}
}

// A different error on an instance that is still there is untouched by any of
// this.
func TestReconcile_UnrelatedNICErrorIsStillReported(t *testing.T) {
	fastGoneChecks(t)
	f := twoTenantHost()
	f.ensureErrs = map[string]error{"bob-container": errors.New(`Invalid devices: Device validation failed for "eth0"`)}
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("an unrelated NIC error was swallowed")
	}
}

var _ = incus.ContainerInfo{}
