package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/agentengine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func requireUsage(t *testing.T, what string, want, got *pb.RunUsage) {
	t.Helper()
	if !proto.Equal(want, got) {
		t.Errorf("%s = {%v}, want {%v}", what, prototext.Format(got), prototext.Format(want))
	}
}

const (
	reported      = pb.RunUsageStatus_RUN_USAGE_STATUS_REPORTED
	aggregateOnly = pb.RunUsageStatus_RUN_USAGE_STATUS_AGGREGATE_ONLY
	unavailable   = pb.RunUsageStatus_RUN_USAGE_STATUS_UNAVAILABLE
)

func row(model string, in, out, cr, cw int64) *pb.RunModelUsage {
	return &pb.RunModelUsage{Model: model, InputTokens: in, OutputTokens: out, CacheReadTokens: cr, CacheWriteTokens: cw}
}

// The artifact.json agent-runtime writes (#3467): modelUsage is Claude Code's
// per-model map, usage its aggregate.
func TestParseArtifact_Usage(t *testing.T) {
	const mu = `"modelUsage":{"claude-opus-4-8":{"inputTokens":10,"outputTokens":3,"cacheReadInputTokens":7,"cacheCreationInputTokens":2,"costUSD":0.01},` +
		`"claude-haiku-4-5":{"inputTokens":1,"outputTokens":1,"cacheReadInputTokens":0,"cacheCreationInputTokens":0}}`
	const agg = `"usage":{"input_tokens":11,"output_tokens":4,"cache_read_input_tokens":7,"cache_creation_input_tokens":2,"service_tier":"standard"}`
	art := func(fields string) []byte {
		return []byte(`{"outputJson":"{}","engine":"claude","model":"claude-opus-4-8"` + fields + `}`)
	}
	tests := []struct {
		name string
		raw  []byte
		want *pb.RunUsage
	}{
		{"modelUsage is reported per model, sorted by id", art("," + mu + "," + agg),
			&pb.RunUsage{Status: reported, Engine: "claude", Models: []*pb.RunModelUsage{
				row("claude-haiku-4-5", 1, 1, 0, 0), row("claude-opus-4-8", 10, 3, 7, 2)}}},
		{"usage alone is one aggregate row with an empty model", art("," + agg),
			&pb.RunUsage{Status: aggregateOnly, Engine: "claude", Models: []*pb.RunModelUsage{row("", 11, 4, 7, 2)}}},
		{"empty modelUsage falls back to usage", art(`,"modelUsage":{},` + agg),
			&pb.RunUsage{Status: aggregateOnly, Engine: "claude", Models: []*pb.RunModelUsage{row("", 11, 4, 7, 2)}}},
		{"a resumed session is flagged", art("," + mu + `,"resumedSession":true`),
			&pb.RunUsage{Status: reported, Engine: "claude", IncludesPriorSession: true, Models: []*pb.RunModelUsage{
				row("claude-haiku-4-5", 1, 1, 0, 0), row("claude-opus-4-8", 10, 3, 7, 2)}}},
		{"no usage at all", art(""), &pb.RunUsage{Status: unavailable}},
		{"null usage", art(`,"usage":null,"modelUsage":null`), &pb.RunUsage{Status: unavailable}},
		{"negative count", art(`,"modelUsage":{"m":{"inputTokens":-1,"outputTokens":0,"cacheReadInputTokens":0,"cacheCreationInputTokens":0}}`), &pb.RunUsage{Status: unavailable}},
		{"fractional count", art(`,"modelUsage":{"m":{"inputTokens":1.5,"outputTokens":0,"cacheReadInputTokens":0,"cacheCreationInputTokens":0}}`), &pb.RunUsage{Status: unavailable}},
		{"string count", art(`,"usage":{"input_tokens":"1","output_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}`), &pb.RunUsage{Status: unavailable}},
		{"count past int64", art(`,"usage":{"input_tokens":9223372036854775808,"output_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}`), &pb.RunUsage{Status: unavailable}},
		{"missing cache field", art(`,"modelUsage":{"m":{"inputTokens":1,"outputTokens":1,"cacheReadInputTokens":0}}`), &pb.RunUsage{Status: unavailable}},
		{"missing aggregate field", art(`,"usage":{"input_tokens":1,"output_tokens":1}`), &pb.RunUsage{Status: unavailable}},
		// Invalid modelUsage is not silently replaced by the aggregate.
		{"invalid modelUsage beside a valid usage", art(`,"modelUsage":{"m":{"inputTokens":-1,"outputTokens":0,"cacheReadInputTokens":0,"cacheCreationInputTokens":0}},` + agg), &pb.RunUsage{Status: unavailable}},
		{"model id outside the model pattern", art(`,"modelUsage":{"bad model":{"inputTokens":1,"outputTokens":0,"cacheReadInputTokens":0,"cacheCreationInputTokens":0}}`), &pb.RunUsage{Status: unavailable}},
		{"modelUsage not an object", art(`,"modelUsage":[1]`), &pb.RunUsage{Status: unavailable}},
		{"model entry not an object", art(`,"modelUsage":{"m":3}`), &pb.RunUsage{Status: unavailable}},
		{"engine name not a plain token", []byte(`{"outputJson":"{}","engine":"Claude Code!",` + agg + `}`), &pb.RunUsage{Status: unavailable}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseArtifact(tc.raw)
			if err != nil {
				t.Fatalf("parseArtifact: %v", err)
			}
			if got.output != "{}" {
				t.Errorf("output = %q, want {}", got.output)
			}
			requireUsage(t, "usage", tc.want, got.usage)
		})
	}
}

// RunAgentSkill's in-box read hands the artifact's usage back with its output.
func TestRunInBoxAgentRun_ReturnsUsage(t *testing.T) {
	s := &AgentSkillServer{inBoxOps: &fakeInBox{artifact: []byte(`{"outputJson":"{\"ok\":true}","engine":"claude",` +
		`"usage":{"input_tokens":1,"output_tokens":2,"cache_read_input_tokens":3,"cache_creation_input_tokens":4}}`)}}
	got, err := s.runInBoxAgentRun("agent-x-container", "/seed", "run-1", "x", agentengine.Resolved{}, "")
	if err != nil {
		t.Fatalf("runInBoxAgentRun: %v", err)
	}
	if got.output != `{"ok":true}` {
		t.Errorf("output = %q", got.output)
	}
	want := &pb.RunUsage{Status: aggregateOnly, Engine: "claude", Models: []*pb.RunModelUsage{row("", 1, 2, 3, 4)}}
	requireUsage(t, "usage", want, got.usage)
}

func TestSumRunUsage(t *testing.T) {
	rep := func(rows ...*pb.RunModelUsage) *pb.RunUsage {
		return &pb.RunUsage{Status: reported, Engine: "claude", Models: rows}
	}
	tests := []struct {
		name    string
		members []*pb.RunUsage
		want    *pb.RunUsage
	}{
		{"members sum by model", []*pb.RunUsage{
			rep(row("a", 1, 2, 3, 4), row("b", 1, 1, 1, 1)),
			rep(row("a", 10, 20, 30, 40)),
		}, rep(row("a", 11, 22, 33, 44), row("b", 1, 1, 1, 1))},
		{"an aggregate member collapses the sum to one aggregate row", []*pb.RunUsage{
			rep(row("a", 1, 2, 3, 4)),
			{Status: aggregateOnly, Engine: "claude", Models: []*pb.RunModelUsage{row("", 5, 5, 5, 5)}},
		}, &pb.RunUsage{Status: aggregateOnly, Engine: "claude", Models: []*pb.RunModelUsage{row("", 6, 7, 8, 9)}}},
		{"a resumed member flags the sum", []*pb.RunUsage{
			rep(row("a", 1, 0, 0, 0)),
			{Status: reported, Engine: "claude", IncludesPriorSession: true, Models: []*pb.RunModelUsage{row("a", 1, 0, 0, 0)}},
		}, &pb.RunUsage{Status: reported, Engine: "claude", IncludesPriorSession: true, Models: []*pb.RunModelUsage{row("a", 2, 0, 0, 0)}}},
		{"members of different engines leave engine empty", []*pb.RunUsage{
			rep(row("a", 1, 0, 0, 0)),
			{Status: reported, Engine: "codex", Models: []*pb.RunModelUsage{row("b", 1, 0, 0, 0)}},
		}, &pb.RunUsage{Status: reported, Models: []*pb.RunModelUsage{row("a", 1, 0, 0, 0), row("b", 1, 0, 0, 0)}}},
		// One member without usage makes the whole sum unknown: a partial sum
		// would read as the run's total.
		{"one unavailable member", []*pb.RunUsage{rep(row("a", 1, 0, 0, 0)), unavailableRunUsage()}, &pb.RunUsage{Status: unavailable}},
		{"one missing member", []*pb.RunUsage{rep(row("a", 1, 0, 0, 0)), nil}, &pb.RunUsage{Status: unavailable}},
		{"no members", nil, &pb.RunUsage{Status: unavailable}},
		{"overflow", []*pb.RunUsage{rep(row("a", 1<<62, 0, 0, 0)), rep(row("a", 1<<62, 0, 0, 0)), rep(row("a", 1<<62, 0, 0, 0))}, &pb.RunUsage{Status: unavailable}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := make([]*pb.RunUsage, len(tc.members))
			for i, m := range tc.members {
				if m != nil {
					before[i] = proto.Clone(m).(*pb.RunUsage)
				}
			}
			got := sumRunUsage(tc.members)
			requireUsage(t, "sum", tc.want, got)
			for i, m := range tc.members {
				if m != nil && !proto.Equal(m, before[i]) {
					t.Errorf("member %d was modified", i)
				}
			}
		})
	}
}

// A graph run's usage is its nodes' usage summed by model, read from each
// node's own run record (#3467).
func TestRunCrewGraph_UsageSumsNodeRecords(t *testing.T) {
	nodeUsage := map[string]*pb.RunUsage{
		"n0": {Status: reported, Engine: "claude", Models: []*pb.RunModelUsage{row("m1", 1, 1, 1, 1)}},
		"n1": {Status: reported, Engine: "claude", Models: []*pb.RunModelUsage{row("m1", 2, 2, 2, 2), row("m2", 5, 0, 0, 0)}},
		"n2": {Status: reported, Engine: "claude", Models: []*pb.RunModelUsage{row("m2", 1, 0, 0, 0)}},
	}
	run := func(t *testing.T, missing string) *pb.CrewRun {
		t.Helper()
		s := NewCrewServer(nil)
		resp, err := s.runCrewGraph(ctxAs("admin", true), graphRequest(3), graphCrew(), "graph-usage-"+missing,
			func(ctx context.Context, node *pb.TaskNode, childID, _ string, _ *pb.RunCrewRequest) (string, error) {
				if node.Id != missing {
					if err := s.runs.Put(ctx, &pb.CrewRun{Id: childID, SkillId: node.GetSkillId(), Usage: nodeUsage[node.Id]}); err != nil {
						return "", err
					}
				}
				return `{"ok":true}`, nil
			})
		if err != nil {
			t.Fatalf("runCrewGraph: %v", err)
		}
		run := resp.GetRun()
		stored, ok, err := s.runs.Get(context.Background(), run.GetId())
		if err != nil || !ok {
			t.Fatalf("stored run: ok=%v err=%v", ok, err)
		}
		requireUsage(t, "stored usage", run.GetUsage(), stored.GetUsage())
		return run
	}
	t.Run("every node reported", func(t *testing.T) {
		want := &pb.RunUsage{Status: reported, Engine: "claude", Models: []*pb.RunModelUsage{row("m1", 3, 3, 3, 3), row("m2", 6, 0, 0, 0)}}
		got := run(t, "")
		requireUsage(t, "usage", want, got.GetUsage())
	})
	t.Run("a node without a usage record", func(t *testing.T) {
		requireUnavailableUsage(t, run(t, "n1").GetUsage())
	})
}

// An A2A crew's members return their artifacts over A2A, which carries no
// usage, so the run reports an explicit UNAVAILABLE: on the RunCrew response
// and on the stored record, never nil and never zeros (#3467).
func TestRunCrew_A2AMembersUsageUnavailable(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	const runID = "run-crew-usage"
	resp, err := h.run(t, runID, func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		return completed("out-of-" + req.ToPeerId), nil
	})
	if err != nil {
		t.Fatalf("runCrew: %v", err)
	}
	requireUnavailableUsage(t, resp.GetRun().GetUsage())
	stored, ok, err := h.crew.runs.Get(context.Background(), runID)
	if err != nil || !ok {
		t.Fatalf("stored run: ok=%v err=%v", ok, err)
	}
	requireUnavailableUsage(t, stored.GetUsage())
}
