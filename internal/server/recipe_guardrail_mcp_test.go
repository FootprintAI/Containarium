package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/mcp"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// Run the real stdio MCP server in a helper process, through the generated
// REST gateway and daemon gate, against the fake container backend.
func TestDeployGate_MCP(t *testing.T) {
	for _, withInput := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid input", false: "missing input"}[withInput], func(t *testing.T) {
			f := newGateFixture(t)
			f.srv.guardrailPolicy = fakePolicyProvider{policy: f.policy}
			mux := runtime.NewServeMux(runtime.WithMetadata(func(context.Context, *http.Request) metadata.MD {
				md, _ := metadata.FromIncomingContext(tenantWithScopes("alice", auth.ScopeContainersWrite))
				return md
			}))
			require.NoError(t, pb.RegisterRecipeServiceHandlerServer(context.Background(), mux, f.srv))
			srv := httptest.NewServer(mux)
			defer srv.Close()
			args := map[string]interface{}{"recipe_id": "gated", "name": "alice"}
			if withInput {
				raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(f.req.GuardrailInput)
				require.NoError(t, err)
				args["guardrail_input"] = json.RawMessage(raw)
			}
			request, err := json.Marshal(mcp.MCPRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: map[string]interface{}{
				"name": "deploy_recipe", "arguments": args,
			}})
			require.NoError(t, err)
			exe, err := os.Executable()
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestDeployGate_MCPHelper$")
			cmd.Env = append(os.Environ(), "CONTAINARIUM_TEST_MCP_GATE_URL="+srv.URL, "CONTAINARIUM_MCP_ALLOW_INSECURE=true")
			cmd.Stdin = bytes.NewReader(append(request, '\n'))
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			require.NoError(t, err, "%s", stderr.String())
			srv.Close()
			var response mcp.MCPResponse
			require.NoError(t, json.Unmarshal(out, &response), "%s", out)
			if withInput {
				require.Nil(t, response.Error, "%s", out)
				require.Equal(t, []string{"alice"}, f.boxes.created)
				assertDelivered(t, f.boxes, f.files)
				require.Equal(t, "exec post_start", f.boxes.events[len(f.boxes.events)-1])
			} else {
				require.NotNil(t, response.Error)
				require.Contains(t, response.Error.Message, "guardrail_input with staging_ref and attestation is required")
				require.Empty(t, f.boxes.created)
			}
			f.assertNoSnapshotLeft(t)
		})
	}
}

// The helper exits before testing prints PASS, keeping stdout pure MCP.
func TestDeployGate_MCPHelper(t *testing.T) {
	url := os.Getenv("CONTAINARIUM_TEST_MCP_GATE_URL")
	if url == "" {
		return
	}
	srv, err := mcp.NewServer(&mcp.Config{ServerURL: url, JWTToken: "test-token", MCPTools: "deploy_recipe"})
	if err == nil {
		err = srv.Start()
	}
	if err != nil {
		_, _ = os.Stderr.WriteString(strings.TrimSpace(err.Error()) + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}
