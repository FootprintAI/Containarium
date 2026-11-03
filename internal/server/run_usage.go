package server

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/footprintai/containarium/internal/coderun/engine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// unavailableRunUsage is the usage every run reports until the daemon reads
// it from the engine's result: an explicit UNAVAILABLE, never nil and never
// zero token counts. It returns a fresh message so callers may modify it.
func unavailableRunUsage() *pb.RunUsage {
	return &pb.RunUsage{Status: pb.RunUsageStatus_RUN_USAGE_STATUS_UNAVAILABLE}
}

// structuredRunUsage reads the token usage from a structured run's log: the
// engine's single JSON result object, decoded with the same rules as
// structuredSessionID — only its top-level keys are consulted, and truncated
// or invalid JSON, or an object over boxRunResultReadLimit, reads as nothing.
//
// A non-empty top-level "modelUsage" (per model, keyed by model id) is
// REPORTED, one row per model sorted by id; otherwise a top-level "usage"
// (the engine's aggregate) is AGGREGATE_ONLY, one row with an empty model. A
// missing key, a negative or non-integer count, or a model id outside
// boxRunModelPattern makes the whole message UNAVAILABLE, never zero counts.
// In "usage" the two cache counts must be present but may be null (read as
// 0); every other count must be a non-null integer.
//
// "model_usage_since_last_result" is not used: Claude Code does not set it on
// --output-format json runs, so a resumed run's counts stay cumulative and
// resumed sets includes_prior_session instead.
func structuredRunUsage(log []byte, resumed bool) *pb.RunUsage {
	if len(log) > boxRunResultReadLimit {
		return unavailableRunUsage()
	}
	var res struct {
		ModelUsage map[string]map[string]json.RawMessage `json:"modelUsage"`
		Usage      map[string]json.RawMessage            `json:"usage"`
	}
	if err := json.Unmarshal(log, &res); err != nil {
		return unavailableRunUsage()
	}
	u := &pb.RunUsage{IncludesPriorSession: resumed, Engine: string(engine.NameClaude)}
	switch {
	case len(res.ModelUsage) > 0:
		u.Status = pb.RunUsageStatus_RUN_USAGE_STATUS_REPORTED
		for model, counts := range res.ModelUsage {
			if !validBoxRunModel(model) {
				return unavailableRunUsage()
			}
			row, ok := boxRunUsageRow(model, counts, "inputTokens", "outputTokens", "cacheReadInputTokens", "cacheCreationInputTokens", false)
			if !ok {
				return unavailableRunUsage()
			}
			u.Models = append(u.Models, row)
		}
		sort.Slice(u.Models, func(i, j int) bool { return u.Models[i].GetModel() < u.Models[j].GetModel() })
	case res.Usage != nil:
		u.Status = pb.RunUsageStatus_RUN_USAGE_STATUS_AGGREGATE_ONLY
		row, ok := boxRunUsageRow("", res.Usage, "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", true)
		if !ok {
			return unavailableRunUsage()
		}
		u.Models = []*pb.RunModelUsage{row}
	default:
		return unavailableRunUsage()
	}
	return u
}

// boxRunUsageRow reads one row's four counts from counts under the given keys. Every
// key must be present; a cache count may be null only when nullCache is set.
func boxRunUsageRow(model string, counts map[string]json.RawMessage, inKey, outKey, cacheReadKey, cacheWriteKey string, nullCache bool) (*pb.RunModelUsage, bool) {
	var vals [4]int64
	for i, key := range []string{inKey, outKey, cacheReadKey, cacheWriteKey} {
		raw, present := counts[key]
		if !present {
			return nil, false
		}
		if string(raw) == "null" && nullCache && i >= 2 {
			continue
		}
		n, ok := boxRunTokenCount(raw)
		if !ok {
			return nil, false
		}
		vals[i] = n
	}
	return &pb.RunModelUsage{Model: model, InputTokens: vals[0], OutputTokens: vals[1], CacheReadTokens: vals[2], CacheWriteTokens: vals[3]}, true
}

// boxRunTokenCount accepts only a plain non-negative JSON integer literal that fits
// in int64: no fraction, exponent, sign, quotes or null.
func boxRunTokenCount(raw json.RawMessage) (int64, bool) {
	s := string(bytes.TrimSpace(raw))
	if s == "" || s[0] < '0' || s[0] > '9' {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
