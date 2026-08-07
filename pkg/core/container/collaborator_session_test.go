package container

import (
	"fmt"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// recordingBackend records the argv of every Exec issued into the container.
// It embeds incus.Backend so it satisfies the 28-method interface with nil
// method bodies for everything the test doesn't exercise; only Exec is real.
type recordingBackend struct {
	incus.Backend
	calls       [][]string
	userdelErr  error // injected failure for the userdel step
	userdelSeen bool
}

func (r *recordingBackend) Exec(_ string, command []string) error {
	r.calls = append(r.calls, command)
	if len(command) > 0 && command[0] == "userdel" {
		r.userdelSeen = true
		return r.userdelErr
	}
	return nil
}

func (r *recordingBackend) index(cmd string) int {
	for i, c := range r.calls {
		if len(c) > 0 && c[0] == cmd {
			return i
		}
	}
	return -1
}

// TestRemoveCollaboratorUser_TerminatesSessionThenForceDeletes pins the #1177
// contract: revoking a collaborator kills the account's live session BEFORE
// deleting it, and the delete is forced (-f) so an in-use account can't block
// removal or survive re-loginnable.
func TestRemoveCollaboratorUser_TerminatesSessionThenForceDeletes(t *testing.T) {
	fake := &recordingBackend{}
	cm := &CollaboratorManager{manager: &Manager{incus: fake}}

	const account = "owner-container-alice"
	if err := cm.removeCollaboratorUser("owner-container", account); err != nil {
		t.Fatalf("removeCollaboratorUser: %v", err)
	}

	pkillIdx := fake.index("pkill")
	loginctlIdx := fake.index("loginctl")
	userdelIdx := fake.index("userdel")

	if loginctlIdx == -1 {
		t.Errorf("expected a loginctl terminate-user call: %v", fake.calls)
	}
	if pkillIdx == -1 {
		t.Fatalf("expected a pkill call to terminate the session: %v", fake.calls)
	}
	if userdelIdx == -1 {
		t.Fatalf("expected a userdel call: %v", fake.calls)
	}

	// Session termination must happen BEFORE the account is deleted — otherwise
	// the live shell survives the revoke.
	if pkillIdx > userdelIdx {
		t.Errorf("pkill (@%d) must run before userdel (@%d): %v", pkillIdx, userdelIdx, fake.calls)
	}

	// pkill targets the account's UID with SIGKILL.
	if got := fake.calls[pkillIdx]; !equalArgs(got, []string{"pkill", "-KILL", "-u", account}) {
		t.Errorf("pkill args = %v, want [pkill -KILL -u %s]", got, account)
	}

	// userdel must force-remove (-f) so an in-use account can't block the
	// delete or be left re-loginnable.
	if got := fake.calls[userdelIdx]; !hasForceFlag(got) {
		t.Errorf("userdel must use -f (force): %v", got)
	}
}

// TestRemoveCollaboratorUser_UserdelErrorSurfaces keeps the existing contract:
// a genuine userdel failure still propagates (the best-effort session-kill
// steps don't mask it).
func TestRemoveCollaboratorUser_UserdelErrorSurfaces(t *testing.T) {
	fake := &recordingBackend{userdelErr: fmt.Errorf("permission denied")}
	cm := &CollaboratorManager{manager: &Manager{incus: fake}}

	err := cm.removeCollaboratorUser("owner-container", "owner-container-bob")
	if err == nil {
		t.Fatal("expected the userdel error to propagate")
	}
	if !fake.userdelSeen {
		t.Error("userdel was never attempted")
	}
	if !strings.Contains(err.Error(), "delete user") {
		t.Errorf("error should wrap the delete-user failure: %v", err)
	}
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// hasForceFlag reports whether any combined short-flag arg (e.g. -rf, -f)
// carries the force flag.
func hasForceFlag(argv []string) bool {
	for _, a := range argv {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "f") {
			return true
		}
	}
	return false
}
