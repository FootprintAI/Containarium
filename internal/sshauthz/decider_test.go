package sshauthz

import (
	"context"
	"errors"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
)

type fakeFacts struct {
	userID string
	ok     bool
	err    error
	calls  int
}

func (f *fakeFacts) Check(context.Context, *pb.AuthorizeSSHRequest) (string, bool, error) {
	f.calls++
	return f.userID, f.ok, f.err
}

type fakeCloud struct {
	resp  *pb.AuthorizeSSHResponse
	err   error
	calls int
	req   *pb.AuthorizeSSHRequest
}

func (f *fakeCloud) AuthorizeSSH(_ context.Context, req *pb.AuthorizeSSHRequest, _ ...grpc.CallOption) (*pb.AuthorizeSSHResponse, error) {
	f.calls++
	f.req = req
	return f.resp, f.err
}

func TestDeciderManagedTable(t *testing.T) {
	req := &pb.AuthorizeSSHRequest{Login: "alice", ClientIp: "192.0.2.10"}
	cloudResp := &pb.AuthorizeSSHResponse{
		Decision:   pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY,
		DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING,
		UserId:     "cloud-user",
	}
	tests := []struct {
		name       string
		facts      *fakeFacts
		cloud      *fakeCloud
		managed    bool
		wantReason pb.SSHDenyReason
		wantCloud  int
	}{
		{name: "local facts deny", facts: &fakeFacts{userID: "alice", ok: false}, cloud: &fakeCloud{resp: cloudResp}, managed: true, wantReason: pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS, wantCloud: 0},
		{name: "local facts error fails closed", facts: &fakeFacts{err: errors.New("facts unavailable")}, cloud: &fakeCloud{resp: cloudResp}, managed: true, wantReason: pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS, wantCloud: 0},
		{name: "cloud transport error", facts: &fakeFacts{userID: "alice", ok: true}, cloud: &fakeCloud{err: errors.New("deadline exceeded")}, managed: true, wantReason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, wantCloud: 1},
		{name: "cloud nil response", facts: &fakeFacts{userID: "alice", ok: true}, cloud: &fakeCloud{}, managed: true, wantReason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, wantCloud: 1},
		{name: "unenrolled never forwards", facts: &fakeFacts{userID: "alice", ok: true}, cloud: &fakeCloud{resp: cloudResp}, managed: false, wantReason: pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS, wantCloud: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&Decider{Local: tt.facts, Cloud: tt.cloud, Managed: tt.managed}).Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got.GetDecision() != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY || got.GetDenyReason() != tt.wantReason {
				t.Fatalf("response = %v, want deny %v", got, tt.wantReason)
			}
			if tt.cloud.calls != tt.wantCloud {
				t.Fatalf("cloud calls = %d, want %d", tt.cloud.calls, tt.wantCloud)
			}
		})
	}
}

func TestDeciderReturnsCloudResponseVerbatimAndForwardsSameRequest(t *testing.T) {
	req := &pb.AuthorizeSSHRequest{Login: "alice", SentinelId: "sentinel-1"}
	resp := &pb.AuthorizeSSHResponse{
		Decision:   pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW,
		UserId:     "user-1",
		DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED,
	}
	cloud := &fakeCloud{resp: resp}
	got, err := (&Decider{Local: &fakeFacts{userID: "alice", ok: true}, Cloud: cloud, Managed: true}).Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != resp {
		t.Fatalf("response was translated: got %p, want exact cloud response %p", got, resp)
	}
	if cloud.req != req {
		t.Fatalf("request was translated: got %p, want exact request %p", cloud.req, req)
	}
}

func TestDeciderCloudNonOKIsUpstreamUnavailable(t *testing.T) {
	cloud := &fakeCloud{err: errors.New("rpc status: unavailable")}
	got, err := (&Decider{Local: &fakeFacts{ok: true}, Cloud: cloud, Managed: true}).Decide(context.Background(), &pb.AuthorizeSSHRequest{})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.GetDenyReason() != pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE {
		t.Fatalf("deny reason = %v, want UPSTREAM_UNAVAILABLE", got.GetDenyReason())
	}
}

var _ CloudAuthorizer = (*fakeCloud)(nil)
