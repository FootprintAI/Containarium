package netbpf

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

// Tier 2 (#661) — cleartext exploit-signature scanning. These mirror the
// compile-time constants in experimental/ebpf-phaseA/netpolicy.bpf.c; the loader
// must not write a slot index >= SigMaxCount or a pattern longer than SigMaxLen.
const (
	SigMaxLen   = 32 // bytes per signature pattern (struct signature.pat)
	SigMaxCount = 32 // signature slots in the `signatures` array map
)

// SignatureEntry is one slot of the BPF `signatures` array map. Field layout
// mirrors `struct signature` in netpolicy.bpf.c: u8 len, u8 enabled, u16 id, then
// SigMaxLen pattern bytes. An entry with Enabled=false (or Len=0) is an inert
// slot the scan skips.
type SignatureEntry struct {
	ID      uint16
	Len     uint8
	Enabled bool
	Pattern [SigMaxLen]byte
}

const signatureValueSize = 4 + SigMaxLen // u8 len + u8 enabled + u16 id + pat[32]

// HasSignatures reports whether the loaded object carries the Tier 2 signature
// map. Like the deny/flow maps it is NOT required by Load — an object built
// before #661 still loads and enforces Tier 0/1; signature scanning just stays
// unavailable until the operator rebuilds netpolicy.bpf.o.
func (l *Loader) HasSignatures() bool {
	return l.coll.Maps[mapSignatures] != nil && l.coll.Maps[mapSigConfig] != nil
}

// SetSignature writes one signature slot (0 <= slot < SigMaxCount). Writing an
// entry with Enabled=false clears the slot. Errors if the object lacks the map.
func (l *Loader) SetSignature(slot uint32, e SignatureEntry) error {
	m := l.coll.Maps[mapSignatures]
	if m == nil {
		return fmt.Errorf("netbpf: signatures map not present (rebuild netpolicy.bpf.o?)")
	}
	if slot >= SigMaxCount {
		return fmt.Errorf("netbpf: signature slot %d out of range (max %d)", slot, SigMaxCount-1)
	}
	if e.Len > SigMaxLen {
		return fmt.Errorf("netbpf: signature pattern len %d exceeds %d", e.Len, SigMaxLen)
	}
	val := signatureValue(e)
	if err := m.Update(&slot, val[:], ebpf.UpdateAny); err != nil {
		return fmt.Errorf("netbpf: update signatures[%d]: %w", slot, err)
	}
	return nil
}

// SetScanEnabled flips the global sig_config gate: the egress program only pays
// the scan cost (the per-packet bpf_loop) when this is true. The loader sets it
// true after populating signatures, false to turn scanning off.
func (l *Loader) SetScanEnabled(on bool) error {
	m := l.coll.Maps[mapSigConfig]
	if m == nil {
		return fmt.Errorf("netbpf: sig_config map not present (rebuild netpolicy.bpf.o?)")
	}
	key := uint32(0)
	var v uint32
	if on {
		v = 1
	}
	if err := m.Update(&key, &v, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("netbpf: update sig_config: %w", err)
	}
	return nil
}

// signatureValue serializes a SignatureEntry into the 36-byte `struct signature`
// layout: u8 len, u8 enabled, u16 id (native byte order), pat[SigMaxLen].
func signatureValue(e SignatureEntry) [signatureValueSize]byte {
	var b [signatureValueSize]byte
	b[0] = e.Len
	if e.Enabled {
		b[1] = 1
	}
	binary.NativeEndian.PutUint16(b[2:4], e.ID)
	copy(b[4:signatureValueSize], e.Pattern[:])
	return b
}
