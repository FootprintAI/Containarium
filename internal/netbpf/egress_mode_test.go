package netbpf

import (
	"encoding/binary"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The BPF config always carries an explicit egress mode: unset follows mode,
// an explicit value is kept independently of mode.
func TestCompileConfig_EgressMode(t *testing.T) {
	cases := []struct {
		name               string
		mode, egress       pb.NetworkPolicyMode
		wantMode, wantEgrs uint8
	}{
		{"unset follows enforce", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, ModeEnforce, ModeEnforce},
		{"unset follows log-only", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, ModeLogOnly, ModeLogOnly},
		{"cross-tenant enforce, egress log-only", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, ModeEnforce, ModeLogOnly},
		{"cross-tenant log-only, egress enforce", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, ModeLogOnly, ModeEnforce},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CompileConfig(5, mustCompile(t, &pb.NetworkPolicy{Tenant: "a", Mode: tc.mode, EgressMode: tc.egress}))
			if got.Mode != tc.wantMode || got.EgressMode != tc.wantEgrs {
				t.Errorf("CompileConfig() mode=%d egress=%d, want mode=%d egress=%d", got.Mode, got.EgressMode, tc.wantMode, tc.wantEgrs)
			}
		})
	}
}

// egress_mode lives in the struct's former pad byte, so the map value stays 8
// bytes and every other field keeps its offset.
func TestVethPolicyValue_EgressModeInPadByte(t *testing.T) {
	b := vethPolicyValue(PolicyConfig{TenantID: 0x01020304, Mode: ModeEnforce, AllowIntra: 1, AllowMetadata: 1, EgressMode: ModeLogOnly})
	if got := binary.NativeEndian.Uint32(b[0:4]); got != 0x01020304 {
		t.Errorf("tenant_id = %#x", got)
	}
	if b[4] != ModeEnforce || b[5] != 1 || b[6] != 1 {
		t.Errorf("mode/allow_intra/allow_metadata = %d/%d/%d", b[4], b[5], b[6])
	}
	if b[7] != ModeLogOnly {
		t.Errorf("egress_mode byte = %d, want %d", b[7], ModeLogOnly)
	}
}

// box_ip is APPENDED to struct policy_cfg (#2618): the first 8 bytes keep their
// layout, and the box's IPv4 follows as its 4 network-order bytes, so an object
// built before it still loads (SetVethPolicy fits the value to the map's size).
func TestVethPolicyValue_BoxIPAppended(t *testing.T) {
	b := vethPolicyValue(PolicyConfig{TenantID: 7, Mode: ModeEnforce, EgressMode: ModeEnforce, BoxIP: [4]byte{10, 100, 0, 10}})
	if len(b) != vethPolicyValueSize || vethPolicyValueSize != 12 {
		t.Fatalf("policy_cfg value is %d bytes (const %d), want 12", len(b), vethPolicyValueSize)
	}
	if got := binary.NativeEndian.Uint32(b[0:4]); got != 7 {
		t.Errorf("tenant_id = %d, want 7", got)
	}
	if b[4] != ModeEnforce || b[7] != ModeEnforce {
		t.Errorf("mode/egress_mode = %d/%d, want %d/%d", b[4], b[7], ModeEnforce, ModeEnforce)
	}
	if got := b[8:12]; string(got) != string([]byte{10, 100, 0, 10}) {
		t.Errorf("box_ip bytes = %v, want 10.100.0.10 in network order", got)
	}
	// Unknown IP: the program reads 0 and skips source validation for the veth.
	z := vethPolicyValue(PolicyConfig{TenantID: 7, Mode: ModeEnforce})
	if binary.NativeEndian.Uint32(z[8:12]) != 0 {
		t.Errorf("box_ip without an IP = %v, want 0", z[8:12])
	}
}

// fitVethPolicyValue adapts the 12-byte value to the loaded object's own
// policy_cfg size: an object from before #2618 has an 8-byte value and must get
// exactly 8 bytes (cilium/ebpf rejects a size mismatch); a larger one is
// zero-padded, which is the "appended field reads as unset" convention.
func TestFitVethPolicyValue(t *testing.T) {
	v := vethPolicyValue(PolicyConfig{TenantID: 1, Mode: ModeLogOnly, BoxIP: [4]byte{10, 0, 0, 1}})
	if got := fitVethPolicyValue(v, 8); len(got) != 8 || string(got) != string(v[:8]) {
		t.Errorf("fit to 8 = %v, want the first 8 bytes %v", got, v[:8])
	}
	if got := fitVethPolicyValue(v, 12); string(got) != string(v[:]) {
		t.Errorf("fit to 12 = %v, want %v", got, v[:])
	}
	if got := fitVethPolicyValue(v, 16); len(got) != 16 || string(got[:12]) != string(v[:]) || got[12] != 0 || got[15] != 0 {
		t.Errorf("fit to 16 = %v, want %v then zeros", got, v[:])
	}
}
