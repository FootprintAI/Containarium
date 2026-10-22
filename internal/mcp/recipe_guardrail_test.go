package mcp

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The complete attestation must survive MCP JSON and the CLI's HTTP path,
// including protobuf timestamps, enum names, int64s and signature bytes.
func TestDeployRecipeTool_GuardrailInput(t *testing.T) {
	want := &pb.GuardrailGateInput{StagingRef: "dataset-v1", Attestation: &pb.GuardrailAttestation{
		SubjectSha256: "digest", Verdict: pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS,
		AttestedAt: timestamppb.New(time.Unix(1700000000, 123)), Signature: []byte{0, 1, 254, 255},
		KindsScanned: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII}, CoverageGaps: 3,
	}}
	raw, err := protojson.Marshal(want)
	require.NoError(t, err)
	var input map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &input))
	var received pb.DeployRecipeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/recipes/gated/deploy", r.URL.Path)
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		body, readErr := io.ReadAll(r.Body)
		assert.NoError(t, readErr)
		assert.NoError(t, protojson.Unmarshal(body, &received))
		_, _ = io.WriteString(w, `{"message":"deployed","url":"https://app.example.com","container":{"name":"alice-container","state":"CONTAINER_STATE_RUNNING"}}`)
	}))
	defer srv.Close()
	out, err := handleDeployRecipe(NewClient(srv.URL, "tok"), map[string]interface{}{
		"recipe_id": "gated", "name": "alice", "gpu": "0", "guardrail_input": input,
		"parameters": map[string]interface{}{"model": "small", "count": float64(2)},
	})
	require.NoError(t, err)
	srv.Close()
	require.True(t, proto.Equal(want, received.GuardrailInput), "got %v", received.GuardrailInput)
	require.Equal(t, "0", received.Gpu)
	require.Equal(t, map[string]string{"model": "small", "count": "2"}, received.Parameters)
	require.Contains(t, out, "deployed")
	require.Contains(t, out, "https://app.example.com")
	require.Contains(t, out, "alice-container (CONTAINER_STATE_RUNNING)")
}

type recipeCallCounter struct {
	API
	calls int
}

// DeployRecipe records whether validation allowed a call to reach the API.
func (c *recipeCallCounter) DeployRecipe(DeployRecipeRequest) (*DeployRecipeResponse, error) {
	c.calls++
	return &DeployRecipeResponse{}, nil
}

// TestDeployRecipeTool_InvalidGuardrailInputSendsNoRequest proves partial
// or malformed gate input is rejected before invoking the backend.
func TestDeployRecipeTool_InvalidGuardrailInputSendsNoRequest(t *testing.T) {
	for _, input := range []interface{}{
		map[string]interface{}{},
		map[string]interface{}{"staging_ref": "ds1"},
		map[string]interface{}{"attestation": map[string]interface{}{}},
		map[string]interface{}{"staging_ref": "ds1", "attestation": nil},
		map[string]interface{}{"staging_ref": "ds1", "attestation": "not an object"},
		map[string]interface{}{"staging_ref": "ds1", "attestation": map[string]interface{}{"verdict": "invalid"}},
	} {
		raw, err := json.Marshal(input)
		require.NoError(t, err)
		t.Run(string(raw), func(t *testing.T) {
			client := &recipeCallCounter{}
			_, err := handleDeployRecipe(client, map[string]interface{}{
				"recipe_id": "gated", "name": "alice", "guardrail_input": input,
			})
			require.ErrorContains(t, err, "guardrail_input")
			require.Zero(t, client.calls)
		})
	}
}

// TestDeployRecipeTool_TransportAndTokenRotation guards MCP's existing CA
// trust, per-request token rotation and refusal of unapproved plaintext.
func TestDeployRecipeTool_TransportAndTokenRotation(t *testing.T) {
	var tokens []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens = append(tokens, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"message":"deployed"}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	t.Setenv(mcpTrustedCAFileEnv, caFile)
	c := NewClient(srv.URL, "stale")
	c.SetTokenFile(tokenFile)
	for _, token := range []string{"first", "rotated"} {
		require.NoError(t, os.WriteFile(tokenFile, []byte(token), 0o600))
		_, err := handleDeployRecipe(c, map[string]interface{}{"recipe_id": "plain", "name": "alice"})
		require.NoError(t, err)
	}
	srv.Close()
	require.Equal(t, []string{"Bearer first", "Bearer rotated"}, tokens)

	t.Setenv(mcpAllowInsecureEnv, "false")
	c = NewClient("http://example.com", "tok")
	_, err := c.DeployRecipe(DeployRecipeRequest{RecipeID: "plain", Name: "alice"})
	require.ErrorContains(t, err, "refuses to send request")
}

// TestDeployRecipeTool_GuardrailSchemaAndScope keeps the gate discoverable
// without changing the tool count or containers:write authorization.
func TestDeployRecipeTool_GuardrailSchemaAndScope(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	require.Len(t, srv.tools, 101)
	for _, tool := range srv.tools {
		if tool.Name != "deploy_recipe" {
			continue
		}
		require.Equal(t, auth.ScopeContainersWrite, tool.RequiredScope)
		for _, text := range []string{"guardrail_input", "staging_ref", "attestation"} {
			require.Contains(t, tool.Description, text)
		}
		schema, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)
		var shape struct {
			Properties map[string]struct {
				Type     string   `json:"type"`
				Required []string `json:"required"`
			} `json:"properties"`
		}
		require.NoError(t, json.Unmarshal(schema, &shape))
		require.Equal(t, "object", shape.Properties["guardrail_input"].Type)
		require.ElementsMatch(t, []string{"staging_ref", "attestation"}, shape.Properties["guardrail_input"].Required)
		require.Contains(t, string(schema), "daemon")
		return
	}
	t.Fatal("deploy_recipe is not registered")
}
