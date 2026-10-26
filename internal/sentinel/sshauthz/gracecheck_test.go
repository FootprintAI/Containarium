package sshauthz

import (
	"errors"
	"strings"
	"testing"
)

func nul(args ...string) []byte { return []byte(strings.Join(args, "\x00") + "\x00") }

func TestCheckParentLoginGrace(t *testing.T) {
	base := []string{"/usr/local/bin/sshpiperd", "-i", "/etc/sshpiper/host_key", "-p", "22"}
	with := func(extra ...string) []byte {
		return nul(append(append(append([]string{}, base...), extra...), "/usr/local/bin/containarium", "sentinel", "ssh-authz-plugin")...)
	}
	tests := []struct {
		name     string
		cmdline  []byte
		err      error
		wantWarn bool
		wantLog  string
	}{
		{name: "flag absent warns", cmdline: with(), wantWarn: true, wantLog: "--login-grace-time"},
		{name: "space form 90s is fine", cmdline: with("--login-grace-time", "90s")},
		{name: "equals form 90s is fine", cmdline: with("--login-grace-time=90s")},
		{name: "single dash space form", cmdline: with("-login-grace-time", "90s")},
		{name: "single dash equals form", cmdline: with("-login-grace-time=90s")},
		{name: "exactly cap plus margin is fine", cmdline: with("--login-grace-time=70s")},
		{name: "30s warns", cmdline: with("--login-grace-time", "30s"), wantWarn: true, wantLog: "30s"},
		{name: "just under the minimum warns", cmdline: with("--login-grace-time=69s"), wantWarn: true},
		{name: "unparsable value warns", cmdline: with("--login-grace-time=abc"), wantWarn: true},
		{name: "flag without value warns", cmdline: nul("sshpiperd", "--login-grace-time"), wantWarn: true},
		{name: "unreadable cmdline does not warn", err: errors.New("no /proc")},
		{name: "empty cmdline does not warn", cmdline: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var warns []string
			CheckParentLoginGrace(func() ([]byte, error) { return tc.cmdline, tc.err }, func(f string, a ...any) {
				warns = append(warns, strings.TrimSpace(fmtSprintf(f, a...)))
			})
			var got []string
			for _, w := range warns {
				if strings.HasPrefix(w, "WARN") {
					got = append(got, w)
				}
			}
			if (len(got) > 0) != tc.wantWarn {
				t.Fatalf("warn=%v want %v; logs=%q", len(got) > 0, tc.wantWarn, warns)
			}
			if tc.wantLog != "" && !strings.Contains(strings.Join(got, "\n"), tc.wantLog) {
				t.Fatalf("warning missing %q: %q", tc.wantLog, got)
			}
		})
	}
}

func TestMinLoginGraceIsCapPlusMargin(t *testing.T) {
	if MinLoginGrace != MaxApprovalWait+LoginGraceMargin {
		t.Fatalf("MinLoginGrace %v", MinLoginGrace)
	}
}
