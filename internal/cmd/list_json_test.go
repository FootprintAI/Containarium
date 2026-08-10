package cmd

import (
	"encoding/json"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// list.go carried its containers as []interface{} and asserted each element
// back to incus.ContainerInfo in three places, and built its --json output
// from map[string]interface{}. Both are the shapes CLAUDE.md names: type
// erasure with no second type behind it, and a wire payload as a map.
//
// The risk in typing them is changing what `--json` emits, so these pin the
// shape rather than the implementation.
func TestListJSONShape(t *testing.T) {
	out := listJSON{
		Containers: []incus.ContainerInfo{{Name: "alice-container", State: "Running"}},
		TotalCount: 1,
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"containers", "total_count"} {
		if _, ok := got[key]; !ok {
			t.Errorf("`list --json` no longer emits %q — anything parsing this output breaks, "+
				"and a struct-tag typo produces valid JSON with the wrong shape", key)
		}
	}
	if len(got) != 2 {
		t.Errorf("`list --json` emits %d keys, want exactly 2: %v", len(got), keysOfRaw(got))
	}
}

func TestGroupedListJSONShape(t *testing.T) {
	out := groupedListJSON{
		GroupBy:    "env",
		Groups:     map[string][]incus.ContainerInfo{"prod": {{Name: "alice-container"}}},
		GroupCount: 1,
		TotalCount: 1,
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"group_by", "groups", "group_count", "total_count"} {
		if _, ok := got[key]; !ok {
			t.Errorf("`list --group-by --json` no longer emits %q", key)
		}
	}
	if len(got) != 4 {
		t.Errorf("emits %d keys, want exactly 4: %v", len(got), keysOfRaw(got))
	}
}

func keysOfRaw(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
