package coderun

import (
	"testing"
	"time"
)

// Command mode (#3322): the one rendering of a shell command under a timeout
// that both the daemon and the CLI run.
func TestBuildShellCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		timeout int
		want    string
	}{
		{"default timeout", "make verify", 0, "timeout -k 5 900 sh -c 'make verify'"},
		{"explicit timeout", "go test ./...", 120, "timeout -k 5 120 sh -c 'go test ./...'"},
		{"negative means default", "true", -5, "timeout -k 5 900 sh -c 'true'"},
		{"quotes are kept out of the outer shell", "echo 'hi'; exit 3", 1, `timeout -k 5 1 sh -c 'echo '\''hi'\''; exit 3'`},
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
	}
	for _, tc := range cases {
		got, err := CommandTimeoutSeconds(tc.d)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("CommandTimeoutSeconds(%s) = (%d, %v), want (%d, err=%v)", tc.d, got, err, tc.want, tc.wantErr)
		}
	}
}
