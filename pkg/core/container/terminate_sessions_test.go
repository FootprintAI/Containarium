package container

import (
	"errors"
	"testing"
)

// TestTerminateAccountSessions_KillsWithoutDeleting pins the shared session
// kill (#2522): loginctl terminate-user, then pkill -KILL -u, inside the box,
// and nothing else — no userdel, no sudoers or authorized_keys edit.
func TestTerminateAccountSessions_KillsWithoutDeleting(t *testing.T) {
	cases := []struct {
		name      string
		pkillExit int
		pkillErr  error
		want      bool
	}{
		{name: "processes killed", pkillExit: 0, want: true},
		{name: "nothing to kill", pkillExit: 1, want: false},
		{name: "exec failed", pkillErr: errors.New("box unreachable"), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &recordingBackend{pkillExit: tc.pkillExit, pkillErr: tc.pkillErr}
			m := NewWithBackend(fake)

			got := m.TerminateAccountSessions("owner-container", "owner-container-alice")
			if got != tc.want {
				t.Errorf("TerminateAccountSessions = %v, want %v", got, tc.want)
			}
			want := [][]string{
				{"loginctl", "terminate-user", "owner-container-alice"},
				{"pkill", "-KILL", "-u", "owner-container-alice"},
			}
			if len(fake.calls) != len(want) {
				t.Fatalf("calls = %v, want %v", fake.calls, want)
			}
			for i := range want {
				if !equalArgs(fake.calls[i], want[i]) {
					t.Errorf("call %d = %v, want %v", i, fake.calls[i], want[i])
				}
			}
		})
	}
}

// TestTerminateAccountSessions_RejectsInvalidAccount keeps a malformed name
// (pkill would read a leading "-" as a flag) from reaching the box.
func TestTerminateAccountSessions_RejectsInvalidAccount(t *testing.T) {
	fake := &recordingBackend{}
	m := NewWithBackend(fake)
	for _, account := range []string{"", "-1", "a b", "alice;reboot", "x/../y"} {
		if m.TerminateAccountSessions("owner-container", account) {
			t.Errorf("%q: reported a kill", account)
		}
	}
	if len(fake.calls) != 0 {
		t.Errorf("invalid accounts reached the box: %v", fake.calls)
	}
}

// TestRemoveCollaboratorUser_UsesSharedSessionKill proves removal still runs
// the same kill sequence before userdel, now through the shared function.
func TestRemoveCollaboratorUser_UsesSharedSessionKill(t *testing.T) {
	fake := &recordingBackend{}
	cm := &CollaboratorManager{manager: NewWithBackend(fake)}
	if err := cm.removeCollaboratorUser("owner-container", "owner-container-alice"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"rm", "-f", "/etc/sudoers.d/owner-container-alice"},
		{"loginctl", "terminate-user", "owner-container-alice"},
		{"pkill", "-KILL", "-u", "owner-container-alice"},
		{"userdel", "-rf", "owner-container-alice"},
	}
	if len(fake.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", fake.calls, want)
	}
	for i := range want {
		if !equalArgs(fake.calls[i], want[i]) {
			t.Errorf("call %d = %v, want %v", i, fake.calls[i], want[i])
		}
	}
}

// TestTerminateJumpAccountSessions_HostPkill pins the host side: one
// pkill -KILL -u on the jump account, reported true only when it matched.
func TestTerminateJumpAccountSessions_HostPkill(t *testing.T) {
	var got [][]string
	exit := error(nil)
	prev := hostPkill
	hostPkill = func(args ...string) error {
		got = append(got, append([]string(nil), args...))
		return exit
	}
	t.Cleanup(func() { hostPkill = prev })

	if !TerminateJumpAccountSessions("owner-container-alice") {
		t.Error("matched pkill should report a kill")
	}
	exit = errors.New("exit status 1")
	if TerminateJumpAccountSessions("owner-container-alice") {
		t.Error("unmatched pkill should not report a kill")
	}
	if TerminateJumpAccountSessions("-1") {
		t.Error("invalid account should not report a kill")
	}
	want := []string{"-KILL", "-u", "owner-container-alice"}
	if len(got) != 2 || !equalArgs(got[0], want) || !equalArgs(got[1], want) {
		t.Errorf("host pkill calls = %v, want two of %v", got, want)
	}
}
