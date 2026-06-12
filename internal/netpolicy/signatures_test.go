package netpolicy

import "testing"

// Mirror the BPF program's compile-time limits (netbpf.SigMaxLen/SigMaxCount);
// the netpolicy package can't import netbpf (that would cycle), so they're
// duplicated here and a violation fails the build's tests.
const (
	sigMaxLen   = 32
	sigMaxCount = 32
)

func TestBuiltinSignatures(t *testing.T) {
	sigs := BuiltinSignatures()
	if len(sigs) == 0 {
		t.Fatal("no built-in signatures")
	}
	if len(sigs) > sigMaxCount {
		t.Fatalf("%d built-ins exceed SigMaxCount (%d)", len(sigs), sigMaxCount)
	}
	seen := make(map[uint16]bool, len(sigs))
	names := make(map[string]bool, len(sigs))
	for _, s := range sigs {
		if s.ID == 0 {
			t.Errorf("signature %q has id 0 (must be nonzero — 0 means no match)", s.Name)
		}
		if seen[s.ID] {
			t.Errorf("duplicate signature id %d", s.ID)
		}
		seen[s.ID] = true
		if s.Name == "" {
			t.Errorf("signature id %d has no name", s.ID)
		}
		if names[s.Name] {
			t.Errorf("duplicate signature name %q", s.Name)
		}
		names[s.Name] = true
		if n := len(s.Pattern); n == 0 || n > sigMaxLen {
			t.Errorf("signature %q pattern length %d out of [1,%d]", s.Name, n, sigMaxLen)
		}
	}
}
