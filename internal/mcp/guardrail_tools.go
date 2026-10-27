package mcp

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// guardrailTools (#2368): a read of the server-side guardrail policy, a thin
// wrapper over the GuardrailPolicyService gateway that
// `containarium guardrail policy get` also calls, printing the same text.
// There is deliberately no write tool: replacing the policy is an admin
// action that stays CLI-only (`containarium guardrail policy set`), so an
// agent cannot loosen the guardrail it runs under.
func guardrailTools() []Tool {
	return []Tool{
		{
			Name: "guardrail_policy_get",
			Description: "Show the server-side guardrail policy: its rules, trusted signer " +
				"key ids, revision and policy hash, or that none is configured. " +
				"Read-only. Mirrors `containarium guardrail policy get`.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleGuardrailPolicyGet,
		},
	}
}

func handleGuardrailPolicyGet(client API, _ map[string]interface{}) (string, error) {
	resp, err := client.GetGuardrailPolicy()
	if err != nil {
		return "", err
	}
	return guardrailpolicy.Describe(resp), nil
}

// GetGuardrailPolicy reads GET /v1/guardrail/policy, the endpoint the CLI's
// HTTP client reads, decoded into the generated type.
func (c *Client) GetGuardrailPolicy() (*pb.GetGuardrailPolicyResponse, error) {
	respBody, err := c.doRequest("GET", "/v1/guardrail/policy", nil)
	if err != nil {
		return nil, err
	}
	out := &pb.GetGuardrailPolicyResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(respBody, out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return out, nil
}
