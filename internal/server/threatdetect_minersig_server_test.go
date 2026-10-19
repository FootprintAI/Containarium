package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func newMinerSigServer(t *testing.T) *ThreatDetectionServer {
	t.Helper()
	s := NewThreatDetectionServer(nil, false, false, "")
	r, err := threatdetect.NewMinerSignatureRule(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.SetMinerSignatureRule(r)
	return s
}

func TestMinerSignatureRPCs_RoundTrip(t *testing.T) {
	s := newMinerSigServer(t)
	list, err := s.ListMinerSignatures(secReadCtx(), &pb.ListMinerSignaturesRequest{})
	if err != nil || list.GetBaselineVersion() == "" || len(list.GetSignatures()) == 0 {
		t.Fatalf("list = %v, %v", list, err)
	}
	base := len(list.GetSignatures())

	add, err := s.AddMinerSignature(badDestAdminCtx(), &pb.AddMinerSignatureRequest{Signature: &pb.MinerSignature{
		Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, Pattern: "SRBMiner*", Label: "SRBMiner", Builtin: true}})
	if err != nil {
		t.Fatal(err)
	}
	want := &pb.MinerSignature{Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, Pattern: "srbminer*", Label: "SRBMiner"}
	if !proto.Equal(add.GetSignature(), want) {
		t.Fatalf("added = %v, want %v (builtin ignored, pattern normalized)", add.GetSignature(), want)
	}
	list, _ = s.ListMinerSignatures(secReadCtx(), &pb.ListMinerSignaturesRequest{})
	if len(list.GetSignatures()) != base+1 {
		t.Fatalf("after add: %d, want %d", len(list.GetSignatures()), base+1)
	}
	if _, err := s.RemoveMinerSignature(badDestAdminCtx(), &pb.RemoveMinerSignatureRequest{
		Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, Pattern: "srbminer*"}); err != nil {
		t.Fatal(err)
	}

	name := pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME
	_, removeUnknown := s.RemoveMinerSignature(badDestAdminCtx(), &pb.RemoveMinerSignatureRequest{Kind: name, Pattern: "srbminer*"})
	_, removeBaseline := s.RemoveMinerSignature(badDestAdminCtx(), &pb.RemoveMinerSignatureRequest{Kind: name, Pattern: "xmrig"})
	_, badHash := s.AddMinerSignature(badDestAdminCtx(), &pb.AddMinerSignatureRequest{Signature: &pb.MinerSignature{Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256, Pattern: "abc"}})
	_, dupBaseline := s.AddMinerSignature(badDestAdminCtx(), &pb.AddMinerSignatureRequest{Signature: &pb.MinerSignature{Kind: name, Pattern: "xmrig"}})
	_, nonAdmin := s.AddMinerSignature(secWriteNonAdminCtx(), &pb.AddMinerSignatureRequest{Signature: &pb.MinerSignature{Kind: name, Pattern: "foo"}})
	codesFor := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"remove unknown", removeUnknown, codes.NotFound},
		{"remove baseline", removeBaseline, codes.FailedPrecondition},
		{"bad sha256", badHash, codes.InvalidArgument},
		{"duplicate of baseline", dupBaseline, codes.AlreadyExists},
		{"non-admin add", nonAdmin, codes.PermissionDenied},
	}
	for _, c := range codesFor {
		if status.Code(c.err) != c.want {
			t.Errorf("%s: %v, want %s", c.name, c.err, c.want)
		}
	}
}

func TestMinerSignatureRPCs_NoRuleUnavailable(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	if _, err := s.ListMinerSignatures(secReadCtx(), &pb.ListMinerSignaturesRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

// TestSetProcessPolicy_KillProcessMerge (#2638): kill_process defaults off,
// is merged field by field (a lone action set never flips it), and an
// explicit false on an override turns a backend true back off.
func TestSetProcessPolicy_KillProcessMerge(t *testing.T) {
	s, _ := newPolicyServer(t)
	if eff := mustEffective(t, s, ""); eff.KillProcess == nil || eff.GetKillProcess() {
		t.Fatalf("default effective kill_process = %v, want explicit false", eff.KillProcess)
	}
	mustSet(t, s, "", &pb.ProcessPolicy{KillProcess: proto.Bool(true)})
	mustSet(t, s, "", &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_FREEZE})
	if eff := mustEffective(t, s, ""); !eff.GetKillProcess() || eff.GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE {
		t.Fatalf("after action-only set: %v, want FREEZE with kill_process kept true", eff)
	}
	if eff := mustEffective(t, s, "box-a"); !eff.GetKillProcess() {
		t.Fatal("container with no override must inherit kill_process=true")
	}
	mustSet(t, s, "box-a", &pb.ProcessPolicy{KillProcess: proto.Bool(false)})
	if eff := mustEffective(t, s, "box-a"); eff.GetKillProcess() {
		t.Fatal("override false must beat backend true")
	}
	mustSet(t, s, "", &pb.ProcessPolicy{KillProcess: proto.Bool(false)})
	if eff := mustEffective(t, s, ""); eff.GetKillProcess() {
		t.Fatal("explicit false must turn it back off")
	}
}

func TestMergeProcessPolicy_KillProcess(t *testing.T) {
	stored := &pb.ProcessPolicy{KillProcess: proto.Bool(true)}
	if got := mergeProcessPolicy(stored, &pb.ProcessPolicy{}); !got.GetKillProcess() {
		t.Error("unset update dropped kill_process")
	}
	if got := mergeProcessPolicy(stored, &pb.ProcessPolicy{KillProcess: proto.Bool(false)}); got.KillProcess == nil || got.GetKillProcess() {
		t.Error("explicit false not applied")
	}
	if got := mergeProcessPolicy(nil, &pb.ProcessPolicy{}); got.KillProcess != nil {
		t.Error("merge invented a kill_process value")
	}
}
