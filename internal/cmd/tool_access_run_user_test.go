package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestRenderRunUserStatus(t *testing.T) {
	tests := []struct {
		name string
		resp *pb.GetBoxRunUserStatusResponse
		want []string
	}{
		{"not recorded", &pb.GetBoxRunUserStatusResponse{RunUser: "ctn-run"}, []string{"no tool-access level recorded", "no run user"}},
		{"user not created", &pb.GetBoxRunUserStatusResponse{RunUser: "ctn-run", ToolAccessRecorded: true, State: pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_NONE}, []string{"does not exist yet", "sign-in: none"}},
		{"signed in", &pb.GetBoxRunUserStatusResponse{RunUser: "ctn-run", ToolAccessRecorded: true, RunUserExists: true, State: pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_INTERACTIVE}, []string{"run user ctn-run", "sign-in: interactive"}},
		{"expired", &pb.GetBoxRunUserStatusResponse{RunUser: "ctn-run", ToolAccessRecorded: true, RunUserExists: true, State: pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED}, []string{"sign-in: expired"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderRunUserStatus("alice", tt.resp)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("output %q missing %q", got, w)
				}
			}
		})
	}
}
