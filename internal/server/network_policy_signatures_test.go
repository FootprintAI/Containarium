package server

import (
	"bytes"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
)

func TestToSigEntry(t *testing.T) {
	e := toSigEntry(netpolicy.Signature{ID: 5, Name: "log4shell", Pattern: []byte("${jndi:")})
	if e.ID != 5 || !e.Enabled || e.Len != 7 {
		t.Fatalf("entry = %+v, want id=5 enabled len=7", e)
	}
	if string(e.Pattern[:e.Len]) != "${jndi:" {
		t.Errorf("pattern = %q, want ${jndi:", string(e.Pattern[:e.Len]))
	}

	// An over-long pattern is truncated to SigMaxLen (defensive — built-ins fit).
	long := bytes.Repeat([]byte("A"), netbpf.SigMaxLen+8)
	e2 := toSigEntry(netpolicy.Signature{ID: 1, Name: "x", Pattern: long})
	if int(e2.Len) != netbpf.SigMaxLen {
		t.Errorf("truncated len = %d, want %d", e2.Len, netbpf.SigMaxLen)
	}
}

// TestBuiltinSignaturesFitMap guards the cross-package invariant the netpolicy
// package can't check itself (it can't import netbpf): every built-in fits the
// BPF map's slot count and pattern width.
func TestBuiltinSignaturesFitMap(t *testing.T) {
	sigs := netpolicy.BuiltinSignatures()
	if len(sigs) > netbpf.SigMaxCount {
		t.Fatalf("%d built-ins exceed SigMaxCount %d", len(sigs), netbpf.SigMaxCount)
	}
	for _, s := range sigs {
		if len(s.Pattern) > netbpf.SigMaxLen {
			t.Errorf("signature %q pattern %d > SigMaxLen %d", s.Name, len(s.Pattern), netbpf.SigMaxLen)
		}
	}
}
