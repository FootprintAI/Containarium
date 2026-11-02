package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// runCrewCapture runs the run_crew handler against a fake daemon and returns
// the request the daemon decoded (as the generated proto type, the way
// grpc-gateway would), the raw body, and the handler error. got is nil when
// the daemon was never reached.
func runCrewCapture(t *testing.T, args map[string]interface{}) (*pb.RunCrewRequest, string, error) {
	t.Helper()
	var got *pb.RunCrewRequest
	var raw string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		got = &pb.RunCrewRequest{}
		assert.NoError(t, protojson.Unmarshal(b, got))
		_, _ = w.Write([]byte(`{"run":{"id":"run-1","state":"RUNNING","traceId":"t-1"}}`))
	}))
	defer server.Close()
	_, err := handleRunCrew(NewClient(server.URL, "test-token"), args)
	return got, raw, err
}

// #3265: model_overrides reaches the daemon request unchanged.
func TestHandleRunCrew_ModelOverridesReachDaemonUnchanged(t *testing.T) {
	got, _, err := runCrewCapture(t, map[string]interface{}{
		"crew_id": "two-engine-crew",
		"model_overrides": map[string]interface{}{
			"hello-agent-claude": "model-a",
			"hello-agent-codex":  "model-b",
		},
	})
	require.NoError(t, err)
	want := &pb.RunCrewRequest{
		CrewId:         "two-engine-crew",
		ModelOverrides: map[string]string{"hello-agent-claude": "model-a", "hello-agent-codex": "model-b"},
	}
	assert.True(t, proto.Equal(want, got), "got %v want %v", got, want)
}

// An absent argument sends nothing.
func TestHandleRunCrew_NoModelOverridesSendsNothing(t *testing.T) {
	for name, args := range map[string]map[string]interface{}{
		"absent": {"crew_id": "c"},
		"empty":  {"crew_id": "c", "model_overrides": map[string]interface{}{}},
	} {
		t.Run(name, func(t *testing.T) {
			got, raw, err := runCrewCapture(t, args)
			require.NoError(t, err)
			assert.NotContains(t, raw, "model_overrides")
			assert.Empty(t, got.GetModelOverrides())
		})
	}
}

// A malformed value is a clear tool error and never reaches the daemon.
func TestHandleRunCrew_MalformedModelOverrides(t *testing.T) {
	cases := map[string]interface{}{
		"a string":          "skill=model",
		"an array":          []interface{}{"skill=model"},
		"a non-string id":   map[string]interface{}{"skill": float64(3)},
		"an empty model id": map[string]interface{}{"skill": ""},
		"an empty skill id": map[string]interface{}{"": "model"},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			got, _, err := runCrewCapture(t, map[string]interface{}{"crew_id": "c", "model_overrides": v})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "model_overrides")
			assert.Nil(t, got, "daemon must not be called")
		})
	}
}
