package threatdetect

import (
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
)

func TestDenyReasonName(t *testing.T) {
	for _, tc := range []struct {
		reason uint8
		want   string
	}{
		{netbpf.DenyReasonPolicy, "policy"},
		{netbpf.DenyReasonVirtualPatch, "virtual-patch"},
		{netbpf.DenyReasonSignature, "signature"},
		{netbpf.DenyReasonConnCap, "conn-cap"},
		{200, "policy"}, // an unknown reason keeps the generic label
	} {
		if got := denyReasonName(tc.reason); got != tc.want {
			t.Errorf("denyReasonName(%d) = %q, want %q", tc.reason, got, tc.want)
		}
	}
}
