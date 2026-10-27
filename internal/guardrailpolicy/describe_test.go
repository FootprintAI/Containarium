package guardrailpolicy_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailpolicy/storetest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestDescribe_RevokedKeys (#2729): `policy get` and the MCP read tool show
// each revoked key with its time and reason, so an admin can see why a Set
// that drops one is refused.
func TestDescribe_RevokedKeys(t *testing.T) {
	gone := storetest.Signer(t, 4, "old key")
	out := guardrailpolicy.Describe(&pb.GetGuardrailPolicyResponse{Configured: true, Policy: &pb.ServerGuardrailPolicy{
		Policy:         storetest.Policy(0),
		RevokedSigners: []*pb.GuardrailRevokedKey{{KeyId: gone.GetKeyId(), RevokedAt: timestamppb.New(time.Date(2026, 10, 2, 3, 4, 5, 0, time.UTC)), Reason: "leaked"}},
	}})
	want := "Revoked keys (1):\n  " + gone.GetKeyId() + "  revoked 2026-10-02T03:04:05Z: leaked\n"
	if !strings.HasSuffix(out, want) {
		t.Fatalf("Describe =\n%s\nwant it to end with\n%s", out, want)
	}
}
