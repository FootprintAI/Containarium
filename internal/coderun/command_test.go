package coderun

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Command mode (#3322): the one rendering of a shell command under a timeout
// that both the daemon and the CLI run.
func TestBuildShellCommand(t *testing.T) {
	probe := "command -v timeout >/dev/null 2>&1 || { echo '" + MissingTimeoutMessage + "' >&2; exit 127; }; "
	cases := []struct {
		name    string
		command string
		timeout int
		want    string
	}{
		{"default timeout", "make verify", 0, probe + "timeout -k 5 900 sh -c 'make verify'"},
		{"explicit timeout", "go test ./...", 120, probe + "timeout -k 5 120 sh -c 'go test ./...'"},
		{"negative means default", "true", -5, probe + "timeout -k 5 900 sh -c 'true'"},
		{"quotes are kept out of the outer shell", "echo 'hi'; exit 3", 1, probe + `timeout -k 5 1 sh -c 'echo '\''hi'\''; exit 3'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BuildShellCommand(tc.command, tc.timeout); got != tc.want {
				t.Errorf("BuildShellCommand(%q, %d) = %q, want %q", tc.command, tc.timeout, got, tc.want)
			}
		})
	}
}

func TestCommandTimeoutSeconds(t *testing.T) {
	cases := []struct {
		d       time.Duration
		want    int
		wantErr bool
	}{
		{0, 0, false},
		{time.Second, 1, false},
		{15 * time.Minute, 900, false},
		{time.Hour, 3600, false},
		{time.Hour + time.Second, 0, true},
		{500 * time.Millisecond, 0, true},
		{-time.Second, 0, true},
		{90 * time.Second, 90, false},
		// #3425: a fractional budget rounds UP, never down (1500ms must not kill at 1s).
		{1500 * time.Millisecond, 2, false},
		{time.Second + time.Nanosecond, 2, false},
		{90*time.Second + time.Millisecond, 91, false},
		{time.Hour + time.Millisecond, 0, true},
	}
	for _, tc := range cases {
		got, err := CommandTimeoutSeconds(tc.d)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("CommandTimeoutSeconds(%s) = (%d, %v), want (%d, err=%v)", tc.d, got, err, tc.want, tc.wantErr)
		}
	}
}

// #3425: a box without a usable `timeout` fails at once with a readable message
// and exit 127, not a bare "timeout: not found". Run under a real sh with
// `timeout` absent from PATH, and with a stub present.
func TestBuildShellCommandWithoutTimeoutBinary(t *testing.T) {
	cmd := BuildShellCommand("echo ran", 5)
	dir := t.TempDir() // empty PATH dir: no timeout; sh is invoked by absolute path
	run := exec.Command("/bin/sh", "-c", cmd)
	run.Env = []string{"PATH=" + dir}
	got, err := run.CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 127 {
		t.Fatalf("exit = %v, want 127; output %q", err, got)
	}
	if !strings.Contains(string(got), "timeout") || !strings.Contains(string(got), "coreutils") {
		t.Errorf("message %q should name the missing timeout command and GNU coreutils", got)
	}
	if strings.Contains(string(got), "ran\n") {
		t.Errorf("command ran unbounded: %q", got)
	}
}
