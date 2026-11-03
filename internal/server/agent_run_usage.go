package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Token usage of skill and crew runs (#3467), read from the artifact.json
// agent-runtime writes. agent-runtime records the engine's aggregate `usage`
// and, for Claude, the result's per-model `modelUsage` (it counts subagents;
// the aggregate does not). Parse rules: prefer modelUsage, else usage as one
// row with an empty model (AGGREGATE_ONLY); a missing, negative or
// non-integer count, an invalid model id, or any other malformed value makes
// the whole usage UNAVAILABLE, never zeros.

// inBoxArtifact is what the daemon keeps from a run's artifact.json.
type inBoxArtifact struct {
	output string
	usage  *pb.RunUsage
}

// artifactFile is artifact.json's top level (agent-runtime/src/artifact.ts).
// The usage fields stay raw: their shape is the engine's, checked below.
type artifactFile struct {
	OutputJSON     string          `json:"outputJson"`
	Error          string          `json:"error"`
	Engine         string          `json:"engine"`
	Usage          json.RawMessage `json:"usage"`
	ModelUsage     json.RawMessage `json:"modelUsage"`
	ResumedSession bool            `json:"resumedSession"`
}

// artifactEnginePattern bounds the engine name agent-runtime records
// (claude | codex | gemini today).
var artifactEnginePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// parseArtifact decodes artifact.json. A non-empty `error` field is returned
// as an error so the run is reported failed. Usage never fails the run: a
// usage the daemon cannot read is UNAVAILABLE.
func parseArtifact(raw []byte) (inBoxArtifact, error) {
	var a artifactFile
	if err := json.Unmarshal(raw, &a); err != nil {
		return inBoxArtifact{}, fmt.Errorf("decode artifact.json: %w", err)
	}
	if a.Error != "" {
		return inBoxArtifact{}, fmt.Errorf("%s", a.Error)
	}
	return inBoxArtifact{output: a.OutputJSON, usage: artifactRunUsage(a)}, nil
}

// artifactRunUsage applies the parse rules above to one artifact.
func artifactRunUsage(a artifactFile) *pb.RunUsage {
	if !artifactEnginePattern.MatchString(a.Engine) {
		return unavailableRunUsage()
	}
	u := &pb.RunUsage{Engine: a.Engine, IncludesPriorSession: a.ResumedSession}
	if present(a.ModelUsage) {
		rows, ok := modelUsageRows(a.ModelUsage)
		if !ok {
			return unavailableRunUsage()
		}
		if len(rows) > 0 {
			u.Status, u.Models = pb.RunUsageStatus_RUN_USAGE_STATUS_REPORTED, rows
			return u
		}
	}
	if !present(a.Usage) {
		return unavailableRunUsage()
	}
	var agg map[string]json.RawMessage
	if json.Unmarshal(a.Usage, &agg) != nil || agg == nil {
		return unavailableRunUsage()
	}
	r, ok := usageRow("", agg, "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
	if !ok {
		return unavailableRunUsage()
	}
	u.Status, u.Models = pb.RunUsageStatus_RUN_USAGE_STATUS_AGGREGATE_ONLY, []*pb.RunModelUsage{r}
	return u
}

// present reports whether a raw field was set to something other than null.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// modelUsageRows reads Claude Code's modelUsage map (model id -> counts) into
// rows sorted by model id. ok is false on any malformed entry.
func modelUsageRows(raw json.RawMessage) ([]*pb.RunModelUsage, bool) {
	var byModel map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &byModel) != nil || byModel == nil {
		return nil, false
	}
	rows := make([]*pb.RunModelUsage, 0, len(byModel))
	for model, counts := range byModel {
		if !validBoxRunModel(model) || counts == nil {
			return nil, false
		}
		r, ok := usageRow(model, counts, "inputTokens", "outputTokens", "cacheReadInputTokens", "cacheCreationInputTokens")
		if !ok {
			return nil, false
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Model < rows[j].Model })
	return rows, true
}

// usageRow reads the four named counts (input, output, cache read, cache
// write) from one usage object. Every one is required.
func usageRow(model string, fields map[string]json.RawMessage, in, out, read, write string) (*pb.RunModelUsage, bool) {
	var n [4]int64
	for i, key := range [4]string{in, out, read, write} {
		v, ok := tokenCount(fields[key])
		if !ok {
			return nil, false
		}
		n[i] = v
	}
	return &pb.RunModelUsage{Model: model, InputTokens: n[0], OutputTokens: n[1], CacheReadTokens: n[2], CacheWriteTokens: n[3]}, true
}

// tokenCount is a JSON integer literal that fits int64 and is not negative.
// A string, a fraction or an exponent form is rejected.
func tokenCount(raw json.RawMessage) (int64, bool) {
	var num json.Number
	if !present(raw) || raw[0] == '"' || json.Unmarshal(raw, &num) != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(num.String(), 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// sumRunUsage is a crew's usage: its members' rows summed by model. Every
// member must have reported usage; one without makes the sum UNAVAILABLE, as
// a partial sum would read as the run's total. A member that reported only an
// aggregate collapses the sum to one AGGREGATE_ONLY row. Engine is kept when
// every member shares it. Members are not modified.
func sumRunUsage(members []*pb.RunUsage) *pb.RunUsage {
	if len(members) == 0 {
		return unavailableRunUsage()
	}
	sum := &pb.RunUsage{Status: pb.RunUsageStatus_RUN_USAGE_STATUS_REPORTED, Engine: members[0].GetEngine()}
	byModel := map[string]*pb.RunModelUsage{}
	for _, m := range members {
		switch m.GetStatus() {
		case pb.RunUsageStatus_RUN_USAGE_STATUS_REPORTED:
		case pb.RunUsageStatus_RUN_USAGE_STATUS_AGGREGATE_ONLY:
			sum.Status = pb.RunUsageStatus_RUN_USAGE_STATUS_AGGREGATE_ONLY
		default:
			return unavailableRunUsage()
		}
		if m.GetEngine() != sum.Engine {
			sum.Engine = ""
		}
		sum.IncludesPriorSession = sum.IncludesPriorSession || m.GetIncludesPriorSession()
		for _, r := range m.GetModels() {
			acc, ok := byModel[r.GetModel()]
			if !ok {
				acc = &pb.RunModelUsage{Model: r.GetModel()}
				byModel[r.GetModel()] = acc
			}
			if !addUsageRow(acc, r) {
				return unavailableRunUsage()
			}
		}
	}
	if sum.Status == pb.RunUsageStatus_RUN_USAGE_STATUS_AGGREGATE_ONLY {
		total := &pb.RunModelUsage{}
		for _, r := range byModel {
			if !addUsageRow(total, r) {
				return unavailableRunUsage()
			}
		}
		sum.Models = []*pb.RunModelUsage{total}
		return sum
	}
	for _, r := range byModel {
		sum.Models = append(sum.Models, r)
	}
	sort.Slice(sum.Models, func(i, j int) bool { return sum.Models[i].Model < sum.Models[j].Model })
	return sum
}

// addUsageRow adds r's counts into acc; false on a negative count or int64
// overflow.
func addUsageRow(acc, r *pb.RunModelUsage) bool {
	for _, p := range [4]struct {
		dst *int64
		v   int64
	}{
		{&acc.InputTokens, r.GetInputTokens()},
		{&acc.OutputTokens, r.GetOutputTokens()},
		{&acc.CacheReadTokens, r.GetCacheReadTokens()},
		{&acc.CacheWriteTokens, r.GetCacheWriteTokens()},
	} {
		if p.v < 0 || *p.dst > math.MaxInt64-p.v {
			return false
		}
		*p.dst += p.v
	}
	return true
}

// graphRunUsage sums a graph run's nodes from each node's own run record (a
// skill node records its usage there; a crew node's record carries its
// crew's). A node with no record, or one that did not succeed, makes the sum
// UNAVAILABLE.
func (s *CrewServer) graphRunUsage(ctx context.Context, nodes []*pb.TaskNodeResult) *pb.RunUsage {
	members := make([]*pb.RunUsage, 0, len(nodes))
	for _, n := range nodes {
		if n.GetState() != pb.TaskNodeState_TASK_NODE_STATE_SUCCEEDED {
			return unavailableRunUsage()
		}
		rec, ok, err := s.runs.Get(ctx, n.GetRunId())
		if err != nil || !ok {
			return unavailableRunUsage()
		}
		members = append(members, rec.GetUsage())
	}
	return sumRunUsage(members)
}
