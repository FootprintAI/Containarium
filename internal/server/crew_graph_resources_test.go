package server

import (
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/capabilities"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func localResourceCrewServer() (*CrewServer, *ContainerServer) {
	containers := &ContainerServer{peerPool: NewPeerPool("local-test", "", nil, "test-pool")}
	containers.capabStore().Record(capabilities.HostFacts{CPUCores: 8, TotalMemoryBytes: 16 << 30, GPUAvailable: true})
	return NewCrewServer(&AgentSkillServer{recipes: &RecipeServer{containers: containers}}), containers
}

// A later ineligible node must reject the whole plan before any earlier node
// provisions a box, including graphs mixing constrained and legacy nodes.
func TestCrewGraph_ResourcesRejectBeforeDispatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*CrewServer, *ContainerServer, *pb.RunCrewRequest)
		want    string
	}{
		{"cpu", func(_ *CrewServer, _ *ContainerServer, r *pb.RunCrewRequest) {
			r.Graph.Nodes[1].Resources.MinCpuCores = 9
		}, "CPU"},
		{"memory", func(_ *CrewServer, _ *ContainerServer, r *pb.RunCrewRequest) {
			r.Graph.Nodes[1].Resources.MinMemoryBytes = 17 << 30
		}, "memory"},
		{"gpu", func(_ *CrewServer, c *ContainerServer, _ *pb.RunCrewRequest) {
			c.capabStore().Record(capabilities.HostFacts{CPUCores: 8, TotalMemoryBytes: 16 << 30, ReportedClass: "gpu"})
		}, "GPU"},
		{"unknown profile", func(_ *CrewServer, c *ContainerServer, _ *pb.RunCrewRequest) {
			c.capabilityStore = capabilities.NewStore()
		}, "profile"},
		{"remote", func(_ *CrewServer, _ *ContainerServer, r *pb.RunCrewRequest) { r.BackendId = "remote-test" }, "local"},
		{"different pool", func(_ *CrewServer, _ *ContainerServer, r *pb.RunCrewRequest) { r.Pool = "other-pool" }, "pool"},
		{"unavailable", func(s *CrewServer, _ *ContainerServer, _ *pb.RunCrewRequest) { s.agents = nil }, "unavailable"},
		{"unhealthy", func(_ *CrewServer, c *ContainerServer, _ *pb.RunCrewRequest) {
			c.localHealthCheckFn = func() bool { return false }
		}, "unhealthy"},
		{"unknown backend identity", func(_ *CrewServer, c *ContainerServer, _ *pb.RunCrewRequest) {
			c.peerPool = NewPeerPool("", "", nil, "test-pool")
		}, "identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, containers := localResourceCrewServer()
			req := graphRequest(2)
			req.Graph.Nodes[1].Resources = &pb.TaskNodeResources{MinCpuCores: 8, MinMemoryBytes: 16 << 30, RequiresGpu: true}
			tc.prepare(s, containers, req)
			_, err := s.runCrewGraph(ctxAs("admin", true), req, graphCrew(), "resources-rejected", func(context.Context, *pb.TaskNode, string, string, *pb.RunCrewRequest) (string, error) {
				t.Error("ineligible graph dispatched a node")
				return "", nil
			})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "n1") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want node-specific %s refusal, got %v", tc.want, err)
			}
		})
	}
}

// The public RunCrew handler must enforce eligibility before entering the
// real runtime path (which is deliberately unwired in this test).
func TestRunCrew_LocalResourcesRejectBeforeRuntime(t *testing.T) {
	s, _ := localResourceCrewServer()
	req := graphRequest(1)
	req.RunId = "resources-public"
	req.Graph.Nodes[0].Resources = &pb.TaskNodeResources{MinCpuCores: 9}
	ctx := ctxAs("admin", true)
	_, err := s.RunCrew(ctx, req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "minimum CPU") {
		t.Fatalf("public handler did not check measured capacity before runtime: %v", err)
	}
	if _, ok, err := s.runs.Get(ctx, req.RunId); err != nil || ok {
		t.Fatalf("preflight refusal must not leave a running record: present=%v err=%v", ok, err)
	}
}

// A fitting profile is only a host eligibility check: constrain placement to
// local, preserve execution inputs, and leave the caller's request untouched.
func TestCrewGraph_ResourceNodesStayLocal(t *testing.T) {
	for _, crewNode := range []bool{false, true} {
		t.Run(map[bool]string{false: "skill", true: "crew"}[crewNode], func(t *testing.T) {
			s, _ := localResourceCrewServer()
			req := graphRequest(1)
			req.Pool = "test-pool"
			req.Graph.Nodes[0].Resources = &pb.TaskNodeResources{MinCpuCores: 8, MinMemoryBytes: 16 << 30, RequiresGpu: true}
			if crewNode {
				req.Graph.Nodes[0].Assignee = &pb.TaskNode_CrewId{CrewId: "freeform-crew"}
			}
			before := proto.Clone(req)
			calls := 0
			resp, err := s.runCrewGraph(ctxAs("admin", true), req, graphCrew(), "resources-local", func(_ context.Context, _ *pb.TaskNode, _, _ string, child *pb.RunCrewRequest) (string, error) {
				calls++
				if child.BackendId != "local-test" || child.Pool != "" {
					t.Errorf("node could be placed remotely: %v", child)
				}
				return "done", nil
			})
			if err != nil || calls != 1 || resp.Run.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED || !proto.Equal(req, before) {
				t.Fatalf("local execution or request isolation failed: calls=%d err=%v", calls, err)
			}
		})
	}
}

// Each minimum is independent; declared classes and missing unrelated fields
// must not replace measured facts or turn an optional constraint into a demand.
func TestCrewGraph_IndividualResourceConstraints(t *testing.T) {
	for _, tc := range []struct {
		name      string
		resources *pb.TaskNodeResources
		facts     capabilities.HostFacts
	}{
		{"cpu only", &pb.TaskNodeResources{MinCpuCores: 4}, capabilities.HostFacts{CPUCores: 4, TotalMemoryBytes: 1 << 30, ReportedClass: "gpu"}},
		{"memory only", &pb.TaskNodeResources{MinMemoryBytes: 8 << 30}, capabilities.HostFacts{CPUCores: 1, TotalMemoryBytes: 8 << 30}},
		{"gpu only", &pb.TaskNodeResources{RequiresGpu: true}, capabilities.HostFacts{CPUCores: 1, TotalMemoryBytes: 1 << 30, GPUAvailable: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, containers := localResourceCrewServer()
			// No peer pool is needed for a standalone daemon's local profile.
			containers.peerPool = nil
			containers.capabStore().Record(tc.facts)
			req := graphRequest(1)
			req.BackendId = "local"
			req.Graph.Nodes[0].Resources = tc.resources
			resp, err := s.runCrewGraph(ctxAs("admin", true), req, graphCrew(), "resources-single", func(_ context.Context, _ *pb.TaskNode, _, _ string, child *pb.RunCrewRequest) (string, error) {
				if child.BackendId != "local" || child.Pool != "" {
					t.Errorf("standalone node not pinned locally: %v", child)
				}
				return "done", nil
			})
			if err != nil || resp.Run.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED {
				t.Fatalf("matching measured profile refused: %v %v", resp, err)
			}
		})
	}
}

// Absent and explicitly empty resources must not demand a profile or change
// legacy backend/pool forwarding, even when the runtime is not wired here.
func TestCrewGraph_UnconstrainedResourcesPreservePlacement(t *testing.T) {
	s := NewCrewServer(nil)
	req := graphRequest(2)
	req.BackendId, req.Pool = "legacy-peer", "legacy-pool"
	req.Concurrency = 1
	req.Graph.Nodes[1].Resources = &pb.TaskNodeResources{}
	var calls int
	resp, err := s.runCrewGraph(ctxAs("admin", true), req, graphCrew(), "resources-legacy", func(_ context.Context, _ *pb.TaskNode, _, _ string, child *pb.RunCrewRequest) (string, error) {
		// Concurrency=1 keeps this counter local to one running worker.
		calls++
		if child != req || child.BackendId != "legacy-peer" || child.Pool != "legacy-pool" {
			t.Error("unconstrained graph placement changed")
		}
		return "done", nil
	})
	if err != nil || calls != 2 || resp.Run.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED {
		t.Fatalf("legacy graph refused: calls=%d err=%v", calls, err)
	}
}

// A refreshed profile must be rechecked before starting a dependent node.
// Its failure is recorded and blocks its descendants; independent work runs.
func TestCrewGraph_ResourceRefreshStopsIneligibleNode(t *testing.T) {
	s, containers := localResourceCrewServer()
	req := graphRequest(4)
	req.Concurrency = 1
	req.Graph.Nodes[1].Resources = &pb.TaskNodeResources{RequiresGpu: true}
	req.Graph.Edges = []*pb.TaskEdge{{NodeId: "n1", DependsOn: "n0"}, {NodeId: "n2", DependsOn: "n1"}}
	resp, err := s.runCrewGraph(ctxAs("admin", true), req, graphCrew(), "resources-refreshed", func(_ context.Context, node *pb.TaskNode, _, _ string, _ *pb.RunCrewRequest) (string, error) {
		if node.Id == "n0" {
			containers.capabStore().Record(capabilities.HostFacts{CPUCores: 8, TotalMemoryBytes: 16 << 30})
		}
		if node.Id == "n1" || node.Id == "n2" {
			t.Error("ineligible node or its descendant executed")
		}
		return node.Id, nil
	})
	if err != nil || resp.Run.State != pb.CrewRunState_CREW_RUN_STATE_FAILED {
		t.Fatalf("refresh failure not recorded: %v %v", resp, err)
	}
	want := map[string]pb.TaskNodeState{"n0": pb.TaskNodeState_TASK_NODE_STATE_SUCCEEDED, "n1": pb.TaskNodeState_TASK_NODE_STATE_FAILED, "n2": pb.TaskNodeState_TASK_NODE_STATE_BLOCKED, "n3": pb.TaskNodeState_TASK_NODE_STATE_SUCCEEDED}
	for _, node := range resp.Run.NodeResults {
		if node.State != want[node.NodeId] {
			t.Errorf("node outcome: %v", node)
		}
		if node.NodeId == "n1" && !strings.Contains(node.Error, "GPU") {
			t.Errorf("resource refusal reason missing: %v", node)
		}
	}
}
