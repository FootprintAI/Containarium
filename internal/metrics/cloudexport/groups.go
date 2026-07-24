package cloudexport

import (
	"fmt"
	"sort"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// definedGroups is the set of metric groups #1081 recognizes as
// independently enableable. UNSPECIFIED is deliberately excluded — it is
// the "no group named" sentinel, never a valid element of an explicit
// list. New groups (e.g. a future apps group) are added here and to the
// collector's per-group registration in one place.
var definedGroups = map[pb.CloudMetricsGroup]bool{
	pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST:      true,
	pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER: true,
	pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM:  true,
}

// DefaultGroup is the group an absent/empty selection resolves to — the
// #1070 host-infra series. Keeping this a named constant makes the
// "absent groups ⇒ host" backward-compatibility rule (v0.60.0 configs
// resume unchanged) explicit at every use site.
const DefaultGroup = pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST

// NormalizeGroups returns the effective set of metric groups to export:
// the input with UNSPECIFIED and duplicates removed and the result sorted
// ascending by enum value for a deterministic persisted form and golden
// series set. An input that is empty (or resolves to empty after dropping
// UNSPECIFIED) becomes [DefaultGroup] — the backward-compatibility rule
// that lets a v0.60.0 host-only config resume exactly as before.
func NormalizeGroups(groups []pb.CloudMetricsGroup) []pb.CloudMetricsGroup {
	seen := map[pb.CloudMetricsGroup]bool{}
	out := make([]pb.CloudMetricsGroup, 0, len(groups))
	for _, g := range groups {
		if g == pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_UNSPECIFIED {
			continue
		}
		if seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	if len(out) == 0 {
		return []pb.CloudMetricsGroup{DefaultGroup}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ValidateGroups rejects an explicit groups list that carries
// CLOUD_METRICS_GROUP_UNSPECIFIED or a value outside the defined set —
// both are client errors the server surfaces as INVALID_ARGUMENT. An
// empty list is valid: it means "default to host", handled by
// NormalizeGroups. Validation is intentionally separate from
// normalization so the server can return a precise error before silently
// coercing a malformed request.
func ValidateGroups(groups []pb.CloudMetricsGroup) error {
	for _, g := range groups {
		if g == pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_UNSPECIFIED {
			return fmt.Errorf("metric group %q is not a valid selection (name a concrete group such as host, container, or platform)", g)
		}
		if !definedGroups[g] {
			return fmt.Errorf("unknown metric group %d", int32(g))
		}
	}
	return nil
}
