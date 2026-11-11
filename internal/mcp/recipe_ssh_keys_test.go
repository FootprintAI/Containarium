package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3514: deploy_recipe's optional ssh_keys reach the daemon through the
// CLI's typed client as DeployRecipeRequest.ssh_keys; omitting them sends
// today's request (no ssh_keys, and no ephemeral keypair is generated).
func TestDeployRecipeTool_SSHKeys(t *testing.T) {
	var bodies []string
	var received []*pb.DeployRecipeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		req := &pb.DeployRecipeRequest{}
		require.NoError(t, protojson.Unmarshal(body, req))
		bodies = append(bodies, string(body))
		received = append(received, req)
		_, _ = io.WriteString(w, `{"message":"deployed"}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")

	keys := []interface{}{"ssh-ed25519 AAAA first", "ssh-ed25519 BBBB second"}
	_, err := handleDeployRecipe(c, map[string]interface{}{"recipe_id": "plain", "name": "alice", "ssh_keys": keys})
	require.NoError(t, err)
	_, err = handleDeployRecipe(c, map[string]interface{}{"recipe_id": "plain", "name": "alice"})
	require.NoError(t, err)
	srv.Close()

	require.Len(t, received, 2)
	require.Equal(t, []string{"ssh-ed25519 AAAA first", "ssh-ed25519 BBBB second"}, received[0].GetSshKeys())
	require.Empty(t, received[1].GetSshKeys())
	require.NotContains(t, bodies[1], "ssh_keys")
}

// A non-string ssh_keys entry is a tool-argument error, sent nowhere.
func TestDeployRecipeTool_SSHKeysMustBeStrings(t *testing.T) {
	client := &recipeCallCounter{}
	_, err := handleDeployRecipe(client, map[string]interface{}{
		"recipe_id": "plain", "name": "alice", "ssh_keys": []interface{}{float64(1)},
	})
	require.Error(t, err)
	require.Zero(t, client.calls)
}

func TestDeployRecipeTool_SSHKeysSchema(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	for _, tool := range srv.tools {
		if tool.Name != "deploy_recipe" {
			continue
		}
		schema, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)
		var shape struct {
			Properties map[string]struct {
				Type  string `json:"type"`
				Items struct {
					Type string `json:"type"`
				} `json:"items"`
			} `json:"properties"`
			Required []string `json:"required"`
		}
		require.NoError(t, json.Unmarshal(schema, &shape))
		require.Equal(t, "array", shape.Properties["ssh_keys"].Type)
		require.Equal(t, "string", shape.Properties["ssh_keys"].Items.Type)
		require.NotContains(t, shape.Required, "ssh_keys")
		return
	}
	t.Fatal("deploy_recipe is not registered")
}
