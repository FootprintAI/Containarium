//go:build !windows

package cmd

import "testing"

func TestMissingCaps(t *testing.T) {
	// All required cap bits set (CHOWN=0, DAC_OVERRIDE=1, FOWNER=3, SETGID=6,
	// SETUID=7) → nothing missing.
	full := uint64(1<<0 | 1<<1 | 1<<3 | 1<<6 | 1<<7)
	if got := missingCaps(full); len(got) != 0 {
		t.Errorf("full caps: missing=%v, want none", got)
	}

	// No caps → all required missing.
	if got := missingCaps(0); len(got) != len(requiredCaps) {
		t.Errorf("zero caps: missing=%v, want all %d", got, len(requiredCaps))
	}

	// Drop only CAP_SETUID (bit 7) → exactly that one is missing.
	noSetuid := full &^ (1 << 7)
	got := missingCaps(noSetuid)
	if len(got) != 1 || got[0] != "CAP_SETUID" {
		t.Errorf("no-setuid: missing=%v, want [CAP_SETUID]", got)
	}
}

func TestPrintDoctor_CountsRequiredFailures(t *testing.T) {
	checks := []doctorCheck{
		{name: "ok-required", ok: true, required: true},
		{name: "fail-required", ok: false, required: true, detail: "x"}, // counts
		{name: "warn-optional", ok: false, required: false},             // not counted
		{name: "fail-required-2", ok: false, required: true},            // counts
	}
	if got := printDoctor(checks); got != 2 {
		t.Fatalf("printDoctor required-failure count = %d, want 2", got)
	}
}
