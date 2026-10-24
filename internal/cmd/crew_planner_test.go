package cmd

import (
	"bytes"
	"context"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type plannerCaptureServer struct {
	pb.UnimplementedCrewServiceServer
	mu  sync.Mutex
	got *pb.PlanTaskGraphRequest
}

func (s *plannerCaptureServer) PlanTaskGraph(_ context.Context, req *pb.PlanTaskGraphRequest) (*pb.PlanTaskGraphResponse, error) {
	s.mu.Lock()
	s.got = proto.Clone(req).(*pb.PlanTaskGraphRequest)
	s.mu.Unlock()
	return &pb.PlanTaskGraphResponse{RunId: "planner-run", Graph: &pb.TaskGraph{Goal: req.Goal,
		Nodes: []*pb.TaskNode{{Id: "review", Goal: "review entry points", Assignee: &pb.TaskNode_SkillId{SkillId: "code-review"}}}}}, nil
}

func TestCrewPlan_FlagsReachDaemonAndStdoutIsReusableGraph(t *testing.T) {
	for _, transport := range []string{"grpc", "http"} {
		t.Run(transport, func(t *testing.T) {
			capture := &plannerCaptureServer{}
			startCrewRunDaemon(t, transport, capture)
			flags := map[string]string{"goal": "review API", "repo": "https://example.com/repo.git", "git-ref": "sha",
				"backend": "backend", "pool": "pool", "git-credential-file": writePlan(t, "credential", "fetch-secret\n")}
			for name, value := range flags {
				old, _ := crewPlanCmd.Flags().GetString(name)
				t.Cleanup(func() { _ = crewPlanCmd.Flags().Set(name, old) })
				if err := crewPlanCmd.Flags().Set(name, value); err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			var diagnostics bytes.Buffer
			crewPlanCmd.SetOut(&output)
			crewPlanCmd.SetErr(&diagnostics)
			t.Cleanup(func() { crewPlanCmd.SetOut(nil); crewPlanCmd.SetErr(nil) })
			if err := runCrewPlan(crewPlanCmd, nil); err != nil {
				t.Fatal(err)
			}
			if diagnostics.String() != "Planner run: planner-run\n" {
				t.Fatalf("stderr must expose the run id for status verification: %q", diagnostics.String())
			}
			want := &pb.PlanTaskGraphRequest{Goal: "review API", Repo: "https://example.com/repo.git", GitRef: "sha",
				BackendId: "backend", Pool: "pool", GitCredential: "fetch-secret"}
			capture.mu.Lock()
			got := capture.got
			capture.mu.Unlock()
			if !proto.Equal(got, want) {
				t.Fatalf("request = %v, want %v", got, want)
			}
			graph := &pb.TaskGraph{}
			if err := protojson.Unmarshal(output.Bytes(), graph); err != nil || graph.Goal != want.Goal {
				t.Fatalf("stdout must contain only a graph: %s, %v", output.String(), err)
			}
			if _, err := loadTaskGraph(writePlan(t, "plan.json", output.String())); err != nil {
				t.Fatalf("plan output must be consumable by plan validate: %v", err)
			}
		})
	}
}
