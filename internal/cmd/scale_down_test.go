package cmd

import (
	"strings"
	"testing"
)

// TestParseIdleMinutes table-drives the CLI's duration→minutes helper.
// Sub-minute durations and unparseable strings must return an error;
// empty string is the special "use default 15" sentinel for the flag's
// default value.
func TestParseIdleMinutes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int32
		wantErr bool
	}{
		{"empty → default 15", "", 15, false},
		{"1m → 1", "1m", 1, false},
		{"15m → 15", "15m", 15, false},
		{"1h → 60", "1h", 60, false},
		{"60m → 60 (same as 1h)", "60m", 60, false},
		{"1h30m → 90", "1h30m", 90, false},
		{"sub-minute rejected (30s)", "30s", 0, true},
		{"zero rejected", "0", 0, true},
		{"negative rejected", "-15m", 0, true},
		{"non-duration rejected", "abc", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIdleMinutes(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseIdleMinutes(%q) = %d, nil; want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIdleMinutes(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseIdleMinutes(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseIdleMinutes_ErrorMessages locks the operator-facing error
// text for the two distinct failure modes — bad duration syntax vs.
// too-small magnitude. Operators grep these strings in CI / scripts.
func TestParseIdleMinutes_ErrorMessages(t *testing.T) {
	_, err := parseIdleMinutes("notaduration")
	if err == nil || !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("syntax error msg = %v, want contains 'invalid duration'", err)
	}
	_, err = parseIdleMinutes("30s")
	if err == nil || !strings.Contains(err.Error(), "at least 1 minute") {
		t.Errorf("sub-minute err = %v, want contains 'at least 1 minute'", err)
	}
}

// TestScaleDownEnable_RequiresUsername verifies the cobra command
// rejects a bare invocation. cobra.ExactArgs(1) ships the rejection
// for us; the test guards against an accidental Args mutation.
func TestScaleDownEnable_RequiresUsername(t *testing.T) {
	err := scaleDownEnableCmd.Args(scaleDownEnableCmd, []string{})
	if err == nil {
		t.Fatal("expected Args validation error for zero positional args")
	}
}

// TestScaleDownStatus_AllowsZeroOrOneArg mirrors the cobra MaximumNArgs(1)
// contract — `scale-down status` (no args, all containers) is valid,
// as is `scale-down status alice`, but two args is not.
func TestScaleDownStatus_AllowsZeroOrOneArg(t *testing.T) {
	if err := scaleDownStatusCmd.Args(scaleDownStatusCmd, []string{}); err != nil {
		t.Errorf("zero args should be allowed: %v", err)
	}
	if err := scaleDownStatusCmd.Args(scaleDownStatusCmd, []string{"alice"}); err != nil {
		t.Errorf("one arg should be allowed: %v", err)
	}
	if err := scaleDownStatusCmd.Args(scaleDownStatusCmd, []string{"alice", "bob"}); err == nil {
		t.Error("two args should be rejected")
	}
}

// TestSleepWakeCmd_RequireUsername guards the cobra contract on the
// stop/start aliases — operator UX expectation is a clear cobra error
// rather than `fmt.Errorf("--server is required")` when the username
// is also missing.
func TestSleepWakeCmd_RequireUsername(t *testing.T) {
	if err := sleepCmd.Args(sleepCmd, []string{}); err == nil {
		t.Error("sleep with no username should fail Args validation")
	}
	if err := wakeCmd.Args(wakeCmd, []string{}); err == nil {
		t.Error("wake with no username should fail Args validation")
	}
}
