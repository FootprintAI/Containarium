package cmd

import (
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium agent run` flag -> RunAgentSkillRequest wiring (#2042).

// resetAgentRunFlags zeroes the package-level flag vars so each table case
// starts from the command's defaults rather than the previous case's values.
func resetAgentRunFlags() {
	agentRunBackendID = ""
	agentRunPool = ""
	agentRunInput = ""
	agentRunGitSource = ""
	agentRunGitRef = ""
	agentRunGitCredentialFile = ""
	agentRunTrackerConnection = ""
}

func TestAgentRun_TrackerConnectionFlagRegistered(t *testing.T) {
	f := agentRunCmd.Flags().Lookup("tracker-connection")
	if f == nil {
		t.Fatal("`agent run` has no --tracker-connection flag")
	}
	if f.DefValue != "" {
		t.Errorf("--tracker-connection default = %q, want empty (no binding)", f.DefValue)
	}
}

func TestBuildAgentRunRequest(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		gitCredential string
		want          *pb.RunAgentSkillRequest
	}{
		{
			name: "no flags",
			want: &pb.RunAgentSkillRequest{SkillId: "hello-agent"},
		},
		{
			name: "tracker connection",
			args: []string{"--tracker-connection", "conn-a"},
			want: &pb.RunAgentSkillRequest{SkillId: "hello-agent", TrackerConnection: "conn-a"},
		},
		{
			name: "every flag",
			args: []string{
				"--backend-id", "local", "--pool", "p1", "--input", `{"q":"hi"}`,
				"--git-source", "https://example.test/repo.git", "--git-ref", "main",
				"--tracker-connection", "conn-a",
			},
			gitCredential: "tok",
			want: &pb.RunAgentSkillRequest{
				SkillId:           "hello-agent",
				BackendId:         "local",
				Pool:              "p1",
				InputJson:         `{"q":"hi"}`,
				GitSource:         "https://example.test/repo.git",
				GitRef:            "main",
				GitCredential:     "tok",
				TrackerConnection: "conn-a",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetAgentRunFlags()
			t.Cleanup(resetAgentRunFlags)
			if err := agentRunCmd.ParseFlags(tt.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			got := buildAgentRunRequest("hello-agent", tt.gitCredential)
			if !proto.Equal(got, tt.want) {
				t.Errorf("request mismatch\n got: %v\nwant: %v", got, tt.want)
			}
		})
	}
}
