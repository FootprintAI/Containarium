package container

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	"github.com/footprintai/containarium/pkg/core/ospkg"
	"github.com/footprintai/containarium/pkg/core/ostype"
	"github.com/footprintai/containarium/pkg/core/sshdpolicy"
)

// Every box — create and bake alike, both families — gets the managed
// key-only sshd drop-in, written before sshd is (re)started so the
// running daemon serves it (#2424).
func TestInstallPackages_WritesKeyOnlySSHDDropIn(t *testing.T) {
	for _, family := range []ostype.OSFamily{ostype.Debian, ostype.RHEL} {
		t.Run(string(family), func(t *testing.T) {
			b := &provisionRecorder{}
			if err := NewWithBackend(b).installPackages("box-container", false, "", nil, "", family); err != nil {
				t.Fatalf("installPackages: %v", err)
			}
			got, ok := b.writes[sshdpolicy.DropInPath]
			if !ok {
				t.Fatalf("drop-in not written to %s; writes: %v", sshdpolicy.DropInPath, keys(b.writes))
			}
			if !bytes.Equal(got, sshdpolicy.DropInContent()) {
				t.Errorf("drop-in content differs from sshdpolicy.DropInContent()")
			}
			if b.modes[sshdpolicy.DropInPath] != sshdpolicy.DropInMode {
				t.Errorf("mode = %q, want %s", b.modes[sshdpolicy.DropInPath], sshdpolicy.DropInMode)
			}
			if !sshdpolicy.Evaluate(string(got)).Compliant() {
				t.Errorf("what we write must itself evaluate as key-only")
			}

			svc := ospkg.ForFamily(family).SSHServiceName()
			restart := slices.IndexFunc(b.execs, func(c []string) bool {
				return slices.Equal(c, []string{"systemctl", "restart", svc})
			})
			if restart < 0 {
				t.Fatalf("sshd must be RESTARTED (not started) so a pre-running sshd picks the drop-in up; execs: %v", b.execs)
			}
			if slices.ContainsFunc(b.execs, func(c []string) bool { return slices.Equal(c, []string{"systemctl", "start", svc}) }) {
				t.Errorf("plain `start` leaves an already-running sshd on the old config")
			}
			mkdir := slices.IndexFunc(b.execs, func(c []string) bool {
				return len(c) == 3 && c[0] == "mkdir" && c[2] == sshdpolicy.DropInDir
			})
			if mkdir < 0 || mkdir > restart {
				t.Errorf("drop-in dir must be created before the restart; mkdir at %d, restart at %d", mkdir, restart)
			}
		})
	}
}

// Unlike the cosmetic login hook, a failed policy write fails provisioning:
// a box the daemon cannot write into is not one it should hand out.
func TestInstallPackages_SSHDDropInWriteFailureIsFatal(t *testing.T) {
	b := &provisionRecorder{writeFileErr: errors.New("push failed"), failPath: sshdpolicy.DropInPath}
	err := NewWithBackend(b).installPackages("box-container", false, "", nil, "", ostype.Debian)
	if err == nil || !strings.Contains(err.Error(), "sshd policy") {
		t.Fatalf("want sshd policy write error, got %v", err)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A new box is stamped with the host-side marker so the reconciler treats a
// later missing or altered drop-in as tampering, not as a first-pass
// backfill (#2424).
func TestMarkSSHDPolicy_SetsHostSideMarker(t *testing.T) {
	var gotBox, gotKey, gotVal string
	b := &incustest.MockBackend{SetConfigFunc: func(box, k, v string) error {
		gotBox, gotKey, gotVal = box, k, v
		return nil
	}}
	NewWithBackend(b).markSSHDPolicy("box-container")
	if gotBox != "box-container" || gotKey != sshdpolicy.MarkerKey || gotVal != sshdpolicy.MarkerValue {
		t.Fatalf("SetConfig(%q, %q, %q), want (box-container, %s, %s)", gotBox, gotKey, gotVal, sshdpolicy.MarkerKey, sshdpolicy.MarkerValue)
	}
}

// Marking is best effort: a failed SetConfig must not fail provisioning.
func TestMarkSSHDPolicy_FailureIsNotFatal(t *testing.T) {
	b := &incustest.MockBackend{SetConfigFunc: func(_, _, _ string) error { return errors.New("boom") }}
	NewWithBackend(b).markSSHDPolicy("box-container") // must not panic or propagate
}
