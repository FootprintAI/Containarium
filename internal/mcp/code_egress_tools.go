package mcp

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/codeegress"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// codeEgressTools is the MCP side of the coding tool's egress allowlist
// (#2378): a thin wrapper over codeegress.Get + codeegress.WriteResponse, the
// functions `containarium code egress-policy get` uses.
//
// Read only. The allowlist is what restricts an agent's coding runs; writing
// it stays with an admin at the CLI (`code egress-policy set`), and the daemon
// refuses a non-admin write either way.
func codeEgressTools() []Tool {
	return []Tool{{
		Name: "code_egress_policy",
		Description: "Show the coding tool's egress allowlist for a tenant (or the cluster default " +
			"when no tenant is given): the stored policy, and the effective one a run takes — " +
			"its source (tenant policy, cluster default, or none = unrestricted), mode, allowed " +
			"CIDRs and domains, and the always-allowed DNS resolver and model gateway. " +
			"Same function as `containarium code egress-policy get`.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant": map[string]interface{}{"type": "string", "description": "Tenant (owner username). Omit for the cluster default."},
			},
		},
		Handler: handleCodeEgressPolicy,
	}}
}

func handleCodeEgressPolicy(client API, args map[string]interface{}) (string, error) {
	resp, err := codeegress.Get(client, getStringArg(args, "tenant", ""))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := codeegress.WriteResponse(&b, resp); err != nil {
		return "", err
	}
	return b.String(), nil
}

// GetCodingToolEgressPolicy reads a policy over the generated REST gateway.
func (c *Client) GetCodingToolEgressPolicy(req *pb.GetCodingToolEgressPolicyRequest) (*pb.GetCodingToolEgressPolicyResponse, error) {
	respBody, err := c.doRequest("GET", codeegress.PolicyPath(req.GetTenant()), nil)
	if err != nil {
		return nil, err
	}
	out := &pb.GetCodingToolEgressPolicyResponse{}
	if err := protojson.Unmarshal(respBody, out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return out, nil
}
