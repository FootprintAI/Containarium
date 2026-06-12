package netbpf

import (
	"encoding/binary"
	"testing"
)

func TestSignatureValueLayout(t *testing.T) {
	var e SignatureEntry
	e.ID = 0x0102
	e.Len = 7
	e.Enabled = true
	copy(e.Pattern[:], []byte("${jndi:"))

	b := signatureValue(e)
	if len(b) != signatureValueSize {
		t.Fatalf("value size = %d, want %d", len(b), signatureValueSize)
	}
	if b[0] != 7 {
		t.Errorf("len byte = %d, want 7", b[0])
	}
	if b[1] != 1 {
		t.Errorf("enabled byte = %d, want 1", b[1])
	}
	if got := binary.NativeEndian.Uint16(b[2:4]); got != 0x0102 {
		t.Errorf("id = %#x, want 0x0102", got)
	}
	if string(b[4:11]) != "${jndi:" {
		t.Errorf("pattern bytes = %q, want ${jndi:", string(b[4:11]))
	}

	// A disabled (empty) slot serializes enabled=0, len=0.
	d := signatureValue(SignatureEntry{})
	if d[0] != 0 || d[1] != 0 {
		t.Errorf("empty slot = len %d enabled %d, want 0/0", d[0], d[1])
	}
}

// TestParseDenyEvent_SignatureTail covers the #661 sig_id tail: a 24-byte sample
// decodes the signature id; an older 20-byte sample (no tail) decodes with
// SigID 0.
func TestParseDenyEvent_SignatureTail(t *testing.T) {
	raw := make([]byte, 24)
	b := binary.NativeEndian
	b.PutUint32(raw[0:4], 7)      // ifindex
	b.PutUint32(raw[4:8], 3)      // tenant
	b.PutUint16(raw[16:18], 8080) // dport
	raw[18] = 6                   // proto = tcp
	raw[19] = DenyReasonSignature
	b.PutUint16(raw[20:22], 42) // sig_id

	ev, err := ParseDenyEvent(raw)
	if err != nil {
		t.Fatalf("ParseDenyEvent: %v", err)
	}
	if ev.Reason != DenyReasonSignature || ev.SigID != 42 || ev.Dport != 8080 || ev.Proto != 6 {
		t.Fatalf("decoded %+v, want reason=SIGNATURE sig=42 dport=8080 proto=6", ev)
	}

	// Pre-#661 object: 20-byte sample, no tail → SigID 0.
	old, err := ParseDenyEvent(raw[:20])
	if err != nil {
		t.Fatalf("ParseDenyEvent(20): %v", err)
	}
	if old.SigID != 0 {
		t.Errorf("20-byte sample SigID = %d, want 0", old.SigID)
	}

	// Too short rejected.
	if _, err := ParseDenyEvent(raw[:19]); err == nil {
		t.Error("a 19-byte sample should be rejected")
	}
}
