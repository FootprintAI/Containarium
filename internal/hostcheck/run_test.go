//go:build !windows

package hostcheck

import "testing"

func TestMissingCaps(t *testing.T) {
	// All required cap bits set (CHOWN=0, DAC_OVERRIDE=1, FOWNER=3, SETGID=6,
	// SETUID=7) → nothing missing.
	full := uint64(1<<0 | 1<<1 | 1<<3 | 1<<6 | 1<<7)
	if got := MissingCaps(full); len(got) != 0 {
		t.Errorf("full caps: missing=%v, want none", got)
	}

	// No caps → all required missing.
	if got := MissingCaps(0); len(got) != len(RequiredCaps) {
		t.Errorf("zero caps: missing=%v, want all %d", got, len(RequiredCaps))
	}

	// Drop only CAP_SETUID (bit 7) → exactly that one is missing.
	noSetuid := full &^ (1 << 7)
	got := MissingCaps(noSetuid)
	if len(got) != 1 || got[0] != "CAP_SETUID" {
		t.Errorf("no-setuid: missing=%v, want [CAP_SETUID]", got)
	}
}

func TestAllRequiredPass(t *testing.T) {
	pass := []Check{{Name: "a", OK: true, Required: true}, {Name: "b", OK: false, Required: false}}
	if !AllRequiredPass(pass) {
		t.Error("optional failure should not flip AllRequiredPass")
	}
	fail := []Check{{Name: "a", OK: false, Required: true}}
	if AllRequiredPass(fail) {
		t.Error("required failure should flip AllRequiredPass")
	}
}
