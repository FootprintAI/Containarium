package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeCodeEgressClient struct {
	set *pb.SetCodingToolEgressPolicyRequest
	get *pb.GetCodingToolEgressPolicyRequest
	del *pb.DeleteCodingToolEgressPolicyRequest
}

func (f *fakeCodeEgressClient) SetCodingToolEgressPolicy(r *pb.SetCodingToolEgressPolicyRequest) (*pb.SetCodingToolEgressPolicyResponse, error) {
	f.set = r
	p := r.GetPolicy()
	return &pb.SetCodingToolEgressPolicyResponse{Policy: &pb.CodingToolEgressPolicy{
		Tenant: p.GetTenant(), Mode: p.GetMode(), EgressCidrs: p.GetEgressCidrs(), EgressDomains: p.GetEgressDomains(), Revision: 3,
	}}, nil
}

func (f *fakeCodeEgressClient) GetCodingToolEgressPolicy(r *pb.GetCodingToolEgressPolicyRequest) (*pb.GetCodingToolEgressPolicyResponse, error) {
	f.get = r
	return &pb.GetCodingToolEgressPolicyResponse{Effective: &pb.EffectiveCodingToolEgressPolicy{
		Tenant: r.GetTenant(), Source: pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_NONE,
	}}, nil
}

func (f *fakeCodeEgressClient) DeleteCodingToolEgressPolicy(r *pb.DeleteCodingToolEgressPolicyRequest) (*pb.DeleteCodingToolEgressPolicyResponse, error) {
	f.del = r
	return &pb.DeleteCodingToolEgressPolicyResponse{}, nil
}

func (f *fakeCodeEgressClient) Close() error { return nil }

func withFakeCodeEgressClient(t *testing.T) *fakeCodeEgressClient {
	t.Helper()
	f := &fakeCodeEgressClient{}
	prev := newCodeEgressClient
	newCodeEgressClient = func() (client.CodeEgressAPI, error) { return f, nil }
	t.Cleanup(func() { newCodeEgressClient = prev })
	return f
}

func TestCodeEgressPolicySet_SendsTypedPolicy(t *testing.T) {
	f := withFakeCodeEgressClient(t)
	var out bytes.Buffer
	err := runCodeEgressSet(&out, []string{"alice"}, "enforce", []string{"192.0.2.0/24"}, []string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	p := f.set.GetPolicy()
	if p.GetTenant() != "alice" || p.GetMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE ||
		len(p.GetEgressCidrs()) != 1 || len(p.GetEgressDomains()) != 1 {
		t.Errorf("sent %+v", p)
	}
	if !strings.Contains(out.String(), "revision 3") {
		t.Errorf("output %q should report the new revision", out.String())
	}
}

func TestCodeEgressPolicySet_NoTenantIsClusterDefault(t *testing.T) {
	f := withFakeCodeEgressClient(t)
	var out bytes.Buffer
	if err := runCodeEgressSet(&out, nil, "log_only", nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.set.GetPolicy().GetTenant() != "" || !strings.Contains(out.String(), "cluster default") {
		t.Errorf("sent %+v, printed %q", f.set.GetPolicy(), out.String())
	}
}

func TestCodeEgressPolicySet_RejectsUnknownModeBeforeDialing(t *testing.T) {
	f := withFakeCodeEgressClient(t)
	var out bytes.Buffer
	if err := runCodeEgressSet(&out, []string{"alice"}, "drop", nil, nil); err == nil {
		t.Fatal("unknown mode must fail")
	}
	if f.set != nil {
		t.Error("a bad mode reached the daemon")
	}
}

func TestCodeEgressPolicyGetAndDelete(t *testing.T) {
	f := withFakeCodeEgressClient(t)
	var out bytes.Buffer
	if err := runCodeEgressGet(&out, []string{"alice"}, false); err != nil {
		t.Fatal(err)
	}
	if f.get.GetTenant() != "alice" || !strings.Contains(out.String(), "unrestricted") {
		t.Errorf("get sent %+v, printed %q", f.get, out.String())
	}
	out.Reset()
	if err := runCodeEgressGet(&out, []string{"alice"}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"CODING_TOOL_EGRESS_POLICY_SOURCE_NONE"`) {
		t.Errorf("--json should print the protojson response, got %q", out.String())
	}
	out.Reset()
	if err := runCodeEgressDelete(&out, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	if f.del.GetTenant() != "alice" {
		t.Errorf("delete sent %+v", f.del)
	}
}
