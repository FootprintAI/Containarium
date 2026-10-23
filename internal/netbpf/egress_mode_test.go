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
