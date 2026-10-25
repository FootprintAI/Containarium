package mcp

import (
	"encoding/json"
	"fmt"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"net/url"
)

type tenantNetworkAPI interface {
	NetworkPolicies() (*pb.ListNetworkPoliciesResponse, error)
	NetworkPolicy(string) (*pb.GetNetworkPolicyResponse, error)
	PatchTenantAccess(*pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error)
}

func (c *Client) tenantRPC(method, path string, req proto.Message, out proto.Message) error {
	var body interface{}
	if req != nil {
		b, err := protojson.Marshal(req)
		if err != nil {
			return err
		}
		body = b
	}
	b, err := c.doRequest(method, path, body)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(b, out)
}
func (c *Client) NetworkPolicies() (*pb.ListNetworkPoliciesResponse, error) {
	out := &pb.ListNetworkPoliciesResponse{}
	err := c.tenantRPC("GET", "/v1/network-policies", nil, out)
	return out, err
}
func (c *Client) NetworkPolicy(tenant string) (*pb.GetNetworkPolicyResponse, error) {
	out := &pb.GetNetworkPolicyResponse{}
	err := c.tenantRPC("GET", "/v1/network-policies/"+url.PathEscape(tenant), nil, out)
	return out, err
}
func (c *Client) PatchTenantAccess(req *pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error) {
	out := &pb.PatchTenantAccessResponse{}
	err := c.tenantRPC("POST", "/v1/network-policies/tenant-access", req, out)
	return out, err
}
func tenantNetworkHandler(operation string) ToolHandler {
	return func(api API, args map[string]interface{}) (string, error) {
		client, ok := api.(tenantNetworkAPI)
		if !ok {
			return "", fmt.Errorf("backend does not support the Tenant network contract")
		}
		var out proto.Message
		var err error
		switch operation {
		case "list":
			out, err = client.NetworkPolicies()
		case "get":
			out, err = client.NetworkPolicy(getStringArg(args, "tenant", ""))
		case "patch":
			raw, e := json.Marshal(args)
			if e != nil {
				return "", e
			}
			req := &pb.PatchTenantAccessRequest{}
			if e = protojson.Unmarshal(raw, req); e != nil {
				return "", e
			}
			out, err = client.PatchTenantAccess(req)
		}
		if err != nil {
			return "", err
		}
		b, err := protojson.Marshal(out)
		return string(b), err
	}
}
func tenantNetworkTools() []Tool {
	empty := map[string]interface{}{"type": "object", "properties": map[string]interface{}{}, "additionalProperties": false}
	change := map[string]interface{}{"type": "object", "properties": map[string]interface{}{
		"destination": map[string]interface{}{"type": "string", "description": "Destination policy whose ingress is edited"}, "expected_revision": map[string]interface{}{"type": "string", "description": "Observed whole-policy SHA256 or absent"},
		"add_sources":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		"remove_sources": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
	}, "required": []string{"destination", "expected_revision"}, "additionalProperties": false}
	return []Tool{

		{Name: "list_network_policies", Description: "Read Tenant network policies. Configured ingress permissions are not TCP test results.", InputSchema: empty, RequiredScope: auth.ScopeNetworkPolicyRead, Handler: tenantNetworkHandler("list")},
		{Name: "get_network_policy", Description: "Read a destination Tenant policy and its full revision for a safe ingress-only edit.", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"tenant": map[string]interface{}{"type": "string", "description": "Destination native network Tenant key"}}, "required": []string{"tenant"}, "additionalProperties": false}, RequiredScope: auth.ScopeNetworkPolicyRead, Handler: tenantNetworkHandler("get")},
		{Name: "patch_tenant_access", Description: "Admin-only atomic ingress-source add/remove with full revision checks. Source A -> destination B changes B.allow_from_tenants. Two changes grant/revoke both directions atomically. Preserves all egress, mode, metadata, preset and deny rules. Tenant-wide access, not port/Box granularity. Does not test TCP.", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"changes": map[string]interface{}{"description": "Revision-checked destination ingress edits; both directions use two changes in one transaction", "type": "array", "items": change, "minItems": 1, "maxItems": 32}}, "required": []string{"changes"}, "additionalProperties": false}, RequiredScope: auth.ScopeNetworkPolicyWrite, Handler: tenantNetworkHandler("patch")},
	}
}
