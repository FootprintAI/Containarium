//go:build !containarium_client

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/agentbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func wantRow(model string, in, out, cr, cw int64) *pb.RunModelUsage {
	return &pb.RunModelUsage{Model: model, InputTokens: in, OutputTokens: out, CacheReadTokens: cr, CacheWriteTokens: cw}
}

// TestStructuredRunUsage covers the parse rules of #3467: top-level keys
// only, modelUsage preferred over usage, and anything doubtful is the whole
// message UNAVAILABLE, never zero counts.
func TestStructuredRunUsage(t *testing.T) {
	const perModel = `{"type":"result","session_id":"s","modelUsage":{` +
		`"claude-b-model":{"inputTokens":10,"outputTokens":20,"cacheReadInputTokens":30,"cacheCreationInputTokens":40,"costUSD":0.5},` +
		`"claude-a-model[1m]":{"inputTokens":1,"outputTokens":2,"cacheReadInputTokens":0,"cacheCreationInputTokens":4}},` +
		`"usage":{"input_tokens":999,"output_tokens":999,"cache_read_input_tokens":999,"cache_creation_input_tokens":999}}`
	const aggregate = `{"type":"result","usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8,"server_tool_use":{"web_search_requests":0}}}`
	big := `{"pad":"` + strings.Repeat("x", boxRunResultReadLimit) + `","usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":1,"cache_creation_input_tokens":1}}`

	reported := pb.RunUsageStatus_RUN_USAGE_STATUS_REPORTED
	aggOnly := pb.RunUsageStatus_RUN_USAGE_STATUS_AGGREGATE_ONLY
	unavail := pb.RunUsageStatus_RUN_USAGE_STATUS_UNAVAILABLE
	cases := []struct {
		name   string
		log    string
		status pb.RunUsageStatus
		rows   []*pb.RunModelUsage
	}{
		{"per-model, sorted by model id, usage ignored", perModel, reported,
			[]*pb.RunModelUsage{wantRow("claude-a-model[1m]", 1, 2, 0, 4), wantRow("claude-b-model", 10, 20, 30, 40)}},
		{"aggregate only", aggregate, aggOnly, []*pb.RunModelUsage{wantRow("", 5, 6, 7, 8)}},
		{"aggregate with null cache fields", `{"usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":null,"cache_creation_input_tokens":null}}`,
			aggOnly, []*pb.RunModelUsage{wantRow("", 5, 6, 0, 0)}},
		{"empty modelUsage falls back to usage", `{"modelUsage":{},"usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`,
			aggOnly, []*pb.RunModelUsage{wantRow("", 5, 6, 7, 8)}},
		{"missing both", `{"type":"result","session_id":"s"}`, unavail, nil},
		{"nested-only keys are ignored", `{"permission_denials":[{"tool_input":{"modelUsage":{"m":{"inputTokens":1,"outputTokens":1,"cacheReadInputTokens":1,"cacheCreationInputTokens":1}},"usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":1,"cache_creation_input_tokens":1}}}]}`, unavail, nil},
		{"truncated", perModel[:len(perModel)-20], unavail, nil},
		{"plain text", "hello, I fixed the bug\n", unavail, nil},
		{"empty", ``, unavail, nil},
		{"top-level array", `[` + aggregate + `]`, unavail, nil},
		{"trailing garbage", aggregate + ` {"x":1}`, unavail, nil},
		{"over the read limit", big, unavail, nil},
		{"negative per-model", `{"modelUsage":{"m":{"inputTokens":-1,"outputTokens":2,"cacheReadInputTokens":3,"cacheCreationInputTokens":4}}}`, unavail, nil},
		{"negative aggregate", `{"usage":{"input_tokens":5,"output_tokens":-6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`, unavail, nil},
		{"fractional", `{"usage":{"input_tokens":5.5,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`, unavail, nil},
		{"exponent", `{"usage":{"input_tokens":1e3,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`, unavail, nil},
		{"quoted number", `{"modelUsage":{"m":{"inputTokens":"1","outputTokens":2,"cacheReadInputTokens":3,"cacheCreationInputTokens":4}}}`, unavail, nil},
		{"overflows int64", `{"usage":{"input_tokens":99999999999999999999,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`, unavail, nil},
		{"null required count", `{"usage":{"input_tokens":null,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`, unavail, nil},
		{"null per-model count", `{"modelUsage":{"m":{"inputTokens":1,"outputTokens":2,"cacheReadInputTokens":null,"cacheCreationInputTokens":4}}}`, unavail, nil},
		{"missing per-model key", `{"modelUsage":{"m":{"inputTokens":1,"outputTokens":2,"cacheReadInputTokens":3}}}`, unavail, nil},
		{"missing aggregate key", `{"usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":7}}`, unavail, nil},
		{"invalid per-model wins over a valid usage", `{"modelUsage":{"m":{"inputTokens":-1,"outputTokens":2,"cacheReadInputTokens":3,"cacheCreationInputTokens":4}},"usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`, unavail, nil},
		{"model id outside the box_run_model pattern", `{"modelUsage":{"../evil model":{"inputTokens":1,"outputTokens":2,"cacheReadInputTokens":3,"cacheCreationInputTokens":4}}}`, unavail, nil},
		{"modelUsage not an object", `{"modelUsage":[1,2]}`, unavail, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := structuredRunUsage([]byte(tc.log), false)
			if u == nil {
				t.Fatal("usage is nil")
			}
			if u.GetStatus() != tc.status {
				t.Fatalf("status = %v, want %v", u.GetStatus(), tc.status)
			}
			if len(u.GetModels()) != len(tc.rows) {
				t.Fatalf("models = %v, want %v", u.GetModels(), tc.rows)
			}
			for i := range tc.rows {
				if !proto.Equal(u.GetModels()[i], tc.rows[i]) {
					t.Errorf("row %d = %v, want %v", i, u.GetModels()[i], tc.rows[i])
				}
			}
			wantEngine := ""
			if tc.status != unavail {
				wantEngine = "claude"
			}
			if u.GetEngine() != wantEngine {
				t.Errorf("engine = %q, want %q", u.GetEngine(), wantEngine)
			}
			if u.GetIncludesPriorSession() {
				t.Error("includes_prior_session set for a fresh run")
			}
		})
	}
}

func TestStructuredRunUsage_ResumedFlag(t *testing.T) {
	const aggregate = `{"usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`
	if u := structuredRunUsage([]byte(aggregate), true); !u.GetIncludesPriorSession() {
		t.Error("resumed run: includes_prior_session = false, want true")
	}
	if u := structuredRunUsage([]byte(aggregate), false); u.GetIncludesPriorSession() {
		t.Error("fresh run: includes_prior_session = true, want false")
	}
}

// listLine is one "R" line of the list script, for a record and a result log.
func listLine(t *testing.T, rec agentbox.RunRecord, exited bool, result string) string {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	b := func(s string) string {
		if s == "" {
			return "-"
		}
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	exit := ""
	if exited {
		exit = fmt.Sprintf("0 %d", time.Now().Unix())
	}
	return fmt.Sprintf("R %s.json %s %s - %s -\n", rec.Name, b(string(data)), b(exit), b(result))
}

func usageRec(name string, resumed bool) agentbox.RunRecord {
	return agentbox.RunRecord{Version: agentbox.RunRecordVersion, Name: name, PID: 1, StartedAt: time.Now().UTC(),
		CaptureMode: agentbox.CaptureCombined, Command: "claude -p 'x' --output-format json", Resumed: resumed}
}

// TestParseBoxRunList_UsagePerRun: each run reports only its own result's
// usage, a resumed run is flagged, and a run without a result (live, or not
// structured) is UNAVAILABLE.
func TestParseBoxRunList_UsagePerRun(t *testing.T) {
	a := `{"modelUsage":{"model-a":{"inputTokens":1,"outputTokens":2,"cacheReadInputTokens":3,"cacheCreationInputTokens":4}}}`
	b := `{"modelUsage":{"model-b":{"inputTokens":10,"outputTokens":20,"cacheReadInputTokens":30,"cacheCreationInputTokens":40}}}`
	out := "B boot\nP \n" +
		listLine(t, usageRec("ra", false), true, a) +
		listLine(t, usageRec("rb", true), true, b) +
		listLine(t, usageRec("live", false), false, "")
	byName := map[string]*pb.BoxRun{}
	for _, r := range parseBoxRunList(out, "/d") {
		byName[r.GetRunName()] = r
	}
	if got := byName["ra"].GetUsage(); len(got.GetModels()) != 1 || !proto.Equal(got.GetModels()[0], wantRow("model-a", 1, 2, 3, 4)) || got.GetIncludesPriorSession() {
		t.Errorf("ra usage = %v, want only model-a, fresh", got)
	}
	if got := byName["rb"].GetUsage(); len(got.GetModels()) != 1 || !proto.Equal(got.GetModels()[0], wantRow("model-b", 10, 20, 30, 40)) || !got.GetIncludesPriorSession() {
		t.Errorf("rb usage = %v, want only model-b, resumed", got)
	}
	requireUnavailableUsage(t, byName["live"].GetUsage())
}

// TestParseBoxRunList_UsageNeedsExit: a result log shipped for a run the
// reader still sees as running is not trusted; usage stays UNAVAILABLE.
func TestParseBoxRunList_UsageNeedsExit(t *testing.T) {
	a := `{"usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":8}}`
	rec := usageRec("r", false)
	rec.BootID = "boot"
	out := "B boot\nP 1\n" + listLine(t, rec, false, a)
	requireUnavailableUsage(t, parseBoxRunList(out, "/d")[0].GetUsage())
}

// TestBoxRunResumed: the record a run writes says
// whether it resumed a session, so ListBoxRuns can flag cumulative counts.
func TestBoxRunResumed(t *testing.T) {
	for _, tc := range []struct {
		req  *pb.StartBoxRunRequest
		want bool
	}{
		{&pb.StartBoxRunRequest{}, false},
		{&pb.StartBoxRunRequest{SessionId: "s1"}, true},
		{&pb.StartBoxRunRequest{ContinueSession: true}, true},
	} {
		if got := boxRunResumed(tc.req); got != tc.want {
			t.Errorf("boxRunResumed(%v) = %v, want %v", tc.req, got, tc.want)
		}
	}
}

// TestStartBoxRun_StructuredUsage runs the fake engine through StartBoxRun and
// ListBoxRuns: a structured run reports its result's per-model usage, a resumed
// one is flagged, and a plain-text run is UNAVAILABLE.
func TestStartBoxRun_StructuredUsage(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	u.writeFakeClaude(t, `case " $* " in
*" --output-format json "*) printf '%s' '{"type":"result","session_id":"sess-1","modelUsage":{"model-x":{"inputTokens":3,"outputTokens":4,"cacheReadInputTokens":5,"cacheCreationInputTokens":6}}}' ;;
*) echo "plain text answer" ;;
esac
`)
	s, _, _ := boxRunStartServer(t, u)
	ctx := tenantCtx("alice")

	for _, req := range []*pb.StartBoxRunRequest{
		{Username: "alice", Prompt: "hi", RunName: "fresh", StructuredOutput: true},
		{Username: "alice", Prompt: "hi", RunName: "resumed", StructuredOutput: true, SessionId: "sess-0"},
		{Username: "alice", Prompt: "hi", RunName: "plain"},
	} {
		resp, err := s.StartBoxRun(ctx, req)
		if err != nil {
			t.Fatalf("StartBoxRun %s: %v", req.GetRunName(), err)
		}
		requireUnavailableUsage(t, resp.GetRun().GetUsage()) // live: nothing yet
	}
	for name, resumed := range map[string]bool{"fresh": false, "resumed": true} {
		done := waitForOutcome(t, s, "alice", name, pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 5*time.Second)
		got := done.GetUsage()
		if got.GetStatus() != pb.RunUsageStatus_RUN_USAGE_STATUS_REPORTED || len(got.GetModels()) != 1 ||
			!proto.Equal(got.GetModels()[0], wantRow("model-x", 3, 4, 5, 6)) {
			t.Errorf("%s: usage = %v, want REPORTED model-x 3/4/5/6", name, got)
		}
		if got.GetIncludesPriorSession() != resumed {
			t.Errorf("%s: includes_prior_session = %v, want %v", name, got.GetIncludesPriorSession(), resumed)
		}
	}
	plain := waitForOutcome(t, s, "alice", "plain", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 5*time.Second)
	requireUnavailableUsage(t, plain.GetUsage())
}
