package client

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestRequestPayloadWireFormat pins the JSON key set of every request
// payload type.
//
// These types replaced inline `map[string]interface{}` literals. The maps
// were wrong in other ways, but they had one accidental virtue: the key
// strings sat right next to the call, so the wire contract was visible.
// Moving to structs moves that contract into a tag, where a single typo
// -- `json:"backend_id"` for a field the daemon reads as `backendId` --
// produces a request that marshals fine, sends fine, and is silently
// ignored by the server.
//
// The `want` lists below are the exact keys the previous map literals
// produced. They are the regression guard for the conversion, not a
// description of it: if a tag is edited, this test fails and the author
// has to confirm the daemon agrees.
func TestRequestPayloadWireFormat(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload any
		want    []string
	}{
		{"createContainerRequest", createContainerRequest{}, []string{
			"backendId", "enablePodman", "gpus", "image", "monitoring",
			"osType", "pool", "resources", "sshKeys", "stack", "username",
		}},
		{"containerResources", containerResources{}, []string{"cpu", "disk", "memory"}},
		{"toggleAutoSleepRequest", toggleAutoSleepRequest{}, []string{"enabled", "idle_threshold_minutes"}},
		{"setContainerTTLRequest", setContainerTTLRequest{}, []string{"duration_seconds"}},
		{"setContainerDeletePolicyRequest", setContainerDeletePolicyRequest{}, []string{"delete_policy"}},
		{"setContainerAttributionRequest", setContainerAttributionRequest{}, []string{"labels"}},
		{"startContainerRequest", startContainerRequest{}, []string{"ready_timeout_seconds", "wait_for_ready"}},
		{"stopContainerRequest", stopContainerRequest{}, []string{"force"}},
		{"resizeContainerRequest", resizeContainerRequest{}, []string{"cpu", "disk", "memory"}},
		{"toggleMonitoringRequest", toggleMonitoringRequest{}, []string{"enabled"}},
		{"setSecretRequest", setSecretRequest{}, []string{"name", "username", "value"}},
		{"setMetricsExportRequest", setMetricsExportRequest{}, []string{"enabled", "provider"}},
		{"refreshTokenRequest", refreshTokenRequest{}, []string{"refresh_token"}},
		{"revokeTokenRequest", revokeTokenRequest{}, []string{"jti"}},
		{"startEgressProxyRequest", startEgressProxyRequest{}, []string{"containerName", "proxyPort", "upstreamPort"}},
		{"installStackRequest", installStackRequest{}, []string{"stackId"}},
		{"setLabelsRequest", setLabelsRequest{}, []string{"labels"}},
		{"deployRecipeRequest", deployRecipeRequest{}, []string{
			"backend_id", "gpu", "name", "parameters", "pool", "recipe_id",
		}},
		{"runAgentSkillRequest", runAgentSkillRequest{}, []string{"backend_id", "input_json", "pool", "skill_id"}},
		{"enqueueAgentTaskRequest", enqueueAgentTaskRequest{}, []string{"input_json", "skill_id"}},
		{"startAgentWorkerRequest", startAgentWorkerRequest{}, []string{"backend_id", "pool", "skill_id", "worker_id"}},
		{"sendAgentTaskRequest", sendAgentTaskRequest{}, []string{"from_skill_id", "input_json", "to_peer_id"}},
		{"runCrewRequest", runCrewRequest{}, []string{"backend_id", "crew_id", "input_json", "pool"}},
		{"addRouteRequest", addRouteRequest{}, []string{
			"container_name", "description", "domain", "target_ip", "target_port",
		}},
		{"addPassthroughRouteRequest", addPassthroughRouteRequest{}, []string{
			"container_name", "description", "external_port", "protocol", "target_ip", "target_port",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := marshalKeys(t, tc.payload)
			sort.Strings(tc.want)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("wire keys changed\n got: %v\nwant: %v", got, tc.want)
			}
		})
	}
}

// marshalKeys returns the sorted top-level JSON keys a payload produces at
// its zero value — i.e. the fields that are unconditionally present.
func marshalKeys(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// The conditional fields must appear only when set. The previous code
// added these keys inside `if` blocks; `omitempty` has to reproduce that
// exactly, or a plain create starts sending keys it never sent before.
func TestConditionalFieldsAreOmittedWhenUnset(t *testing.T) {
	t.Run("createContainerRequest", func(t *testing.T) {
		keys := marshalKeys(t, createContainerRequest{})
		for _, absent := range []string{
			"gitSource", "gitRef", "gitCredential", "workspacePath",
			"ttlSeconds", "idleStopMinutes", "deleteAfterStoppedSeconds",
		} {
			if contains(keys, absent) {
				t.Errorf("%q must be absent when unset", absent)
			}
		}
	})

	t.Run("storageClass", func(t *testing.T) {
		if contains(marshalKeys(t, containerResources{}), "storageClass") {
			t.Error("storageClass must be absent when unset")
		}
		b, _ := json.Marshal(containerResources{StorageClass: "fast"})
		if !strings.Contains(string(b), `"storageClass":"fast"`) {
			t.Errorf("storageClass must be sent when set, got %s", b)
		}
	})

	t.Run("revokeTokenRequest", func(t *testing.T) {
		keys := marshalKeys(t, revokeTokenRequest{JTI: "j"})
		if contains(keys, "reason") || contains(keys, "expires_at") {
			t.Errorf("optional revoke fields must be absent when unset, got %v", keys)
		}
	})

	t.Run("setMetricsExportRequest groups", func(t *testing.T) {
		if contains(marshalKeys(t, setMetricsExportRequest{}), "groups") {
			t.Error("groups must be absent when empty so a host-only call stays byte-identical (#1081)")
		}
	})
}

// The git fields travel as a set: all four present (even when empty) once
// a source is given, all four absent otherwise. That is what the previous
// `if git.Source != ""` block did, and plain strings with omitempty would
// silently drop the empty ones.
func TestGitFieldsTravelTogether(t *testing.T) {
	empty := ""
	src := "https://example.test/repo.git"
	req := createContainerRequest{
		GitSource:     &src,
		GitRef:        &empty,
		GitCredential: &empty,
		WorkspacePath: &empty,
	}
	keys := marshalKeys(t, req)
	for _, k := range []string{"gitSource", "gitRef", "gitCredential", "workspacePath"} {
		if !contains(keys, k) {
			t.Errorf("%q must be present when a git source is set, even if empty", k)
		}
	}
}

// osType is the generated enum, and json.Marshal emits its numeric value —
// which is what the previous map put on the wire and what protojson
// accepts. Encoding it as the enum's *name* instead would be a silent
// wire change.
func TestOSTypeMarshalsAsItsNumericEnumValue(t *testing.T) {
	b, err := json.Marshal(createContainerRequest{OSType: pb.OSType_OS_TYPE_ROCKY_9})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `"osType":` + itoa(int(pb.OSType_OS_TYPE_ROCKY_9))
	if !strings.Contains(string(b), want) {
		t.Errorf("osType encoding changed: want %s in %s", want, b)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
