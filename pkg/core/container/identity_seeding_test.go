package container

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	"github.com/footprintai/containarium/pkg/core/ostype"
)

// The collapse contract (#1488 Finding 2): identity seeding pays one
// in-guest exec per function, not one per command. Each Incus Exec is a
// websocket-upgrading operation at ~50-150ms, so the exec COUNT is the
// behavior under test, alongside the safety of the generated script.

func TestShellQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice", "'alice'"},
		{"", "''"},
		{"a b", "'a b'"},
		{"a'b", `'a'\''b'`},
		{"'; touch /pwned; '", `''\''; touch /pwned; '\'''`},
		{"$HOME `id` \\", "'$HOME `id` \\'"},
	}
	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestShellJoin(t *testing.T) {
	got := shellJoin([]string{"adduser", "--gecos", "", "a'b"})
	want := `'adduser' '--gecos' '' 'a'\''b'`
	if got != want {
		t.Errorf("shellJoin = %s, want %s", got, want)
	}
}

// seedRecorder captures every Exec and WriteFile.
type seedRecorder struct {
	execs  [][]string
	writes []struct {
		path, mode string
		content    string
	}
}

func newSeedBackend() (*incustest.MockBackend, *seedRecorder) {
	rec := &seedRecorder{}
	mock := incustest.NewMockBackend()
	mock.ExecFunc = func(_ string, command []string) error {
		rec.execs = append(rec.execs, command)
		return nil
	}
	mock.WriteFileFunc = func(_, path string, content []byte, mode string) error {
		rec.writes = append(rec.writes, struct {
			path, mode string
			content    string
		}{path, mode, string(content)})
		return nil
	}
	return mock, rec
}

func TestCreateUser_SingleExecPerFamily(t *testing.T) {
	cases := []struct {
		family      ostype.OSFamily
		wantCreate  string
		wantSudoGrp string
	}{
		{ostype.Debian, "'adduser'", "'sudo'"},
		{ostype.RHEL, "'useradd'", "'wheel'"},
	}
	for _, c := range cases {
		t.Run(string(c.family), func(t *testing.T) {
			mock, rec := newSeedBackend()
			m := NewWithBackend(mock)

			if err := m.createUser("alice-container", "alice", c.family); err != nil {
				t.Fatalf("createUser: %v", err)
			}

			if len(rec.execs) != 1 {
				t.Fatalf("createUser issued %d execs, want exactly 1: %v", len(rec.execs), rec.execs)
			}
			argv := rec.execs[0]
			if len(argv) != 3 || argv[0] != "/bin/sh" || argv[1] != "-c" {
				t.Fatalf("exec argv = %v, want [/bin/sh -c <script>]", argv)
			}
			script := argv[2]
			for _, frag := range []string{c.wantCreate, "'usermod'", c.wantSudoGrp, "'podman'", "|| true", "'alice'"} {
				if !strings.Contains(script, frag) {
					t.Errorf("script missing %s:\n%s", frag, script)
				}
			}

			if len(rec.writes) != 1 {
				t.Fatalf("createUser issued %d writes, want 1 (sudoers): %+v", len(rec.writes), rec.writes)
			}
			w := rec.writes[0]
			if w.path != "/etc/sudoers.d/alice" || w.mode != "0440" {
				t.Errorf("sudoers write = %q mode %q", w.path, w.mode)
			}
		})
	}
}

// A hostile username must reach the script only inside single quotes —
// the quoted rendition appears, the raw breakout never does.
func TestCreateUser_HostileUsernameIsQuoted(t *testing.T) {
	const evil = "eve'; touch /pwned; '"
	mock, rec := newSeedBackend()
	m := NewWithBackend(mock)

	if err := m.createUser("c", evil, ostype.Debian); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	script := rec.execs[0][2]
	if !strings.Contains(script, shellQuote(evil)) {
		t.Errorf("script does not contain the quoted username:\n%s", script)
	}
	if strings.Contains(script, "'"+evil+"'") {
		t.Errorf("script contains a naively-quoted breakout:\n%s", script)
	}
}

func TestAddSSHKeys_StagesOnceThenPlacesOnce(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMw0GUYQZVPWxSAC4T8RdKFGqzb8jxbFFM/SB6ILi1Ji test@host"
	mock, rec := newSeedBackend()
	m := NewWithBackend(mock)

	if err := m.addSSHKeys("alice-container", "alice", []string{key, "  ", ""}); err != nil {
		t.Fatalf("addSSHKeys: %v", err)
	}

	if len(rec.writes) != 1 {
		t.Fatalf("addSSHKeys issued %d writes, want 1 (staging): %+v", len(rec.writes), rec.writes)
	}
	w := rec.writes[0]
	if w.path != addSSHKeysStagingPath("alice") || w.mode != "0600" {
		t.Errorf("staging write = %q mode %q", w.path, w.mode)
	}
	if w.content != key+"\n" {
		t.Errorf("staged content = %q", w.content)
	}

	if len(rec.execs) != 1 {
		t.Fatalf("addSSHKeys issued %d execs, want exactly 1: %v", len(rec.execs), rec.execs)
	}
	argv := rec.execs[0]
	// [/bin/sh -c <script> sh <sshDir> <username> <staging>] — data rides
	// as positional parameters, never spliced into the script text.
	if len(argv) != 7 || argv[0] != "/bin/sh" || argv[1] != "-c" {
		t.Fatalf("exec argv = %v", argv)
	}
	if argv[4] != "/home/alice/.ssh" || argv[5] != "alice" || argv[6] != addSSHKeysStagingPath("alice") {
		t.Errorf("positional params = %v", argv[4:])
	}
	if strings.Contains(argv[2], "alice") {
		t.Errorf("script text embeds the username instead of using positional params:\n%s", argv[2])
	}
}

func TestAddSSHKeys_InvalidKeyRejectedBeforeAnySideEffect(t *testing.T) {
	mock, rec := newSeedBackend()
	m := NewWithBackend(mock)

	if err := m.addSSHKeys("alice-container", "alice", []string{"YOUR_KEY_HERE"}); err == nil {
		t.Fatal("addSSHKeys accepted an invalid key")
	}
	if len(rec.writes) != 0 || len(rec.execs) != 0 {
		t.Errorf("invalid key still caused side effects: writes=%+v execs=%v", rec.writes, rec.execs)
	}
}
