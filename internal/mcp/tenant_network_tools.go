package mcp

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// tenantNetworkAPI is the slice of the MCP backend the Tenant-network tools
// need. The Host MCP client implements it over REST with typed protobuf
// request/response values; no handler builds a request by re-marshalling raw
// tool arguments.
type tenantNetworkAPI interface {
	NetworkPolicies() (*pb.ListNetworkPoliciesResponse, error)
	NetworkPolicy(string) (*pb.GetNetworkPolicyResponse, error)
	PatchTenantAccess(*pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error)
}

// tenantRPC performs one REST round trip with a typed request and response.
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
	return (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, out)
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

// parsePatchTenantAccessArgs builds the proto request field by field from the
// tool arguments; the raw argument map is never marshalled into the request.
func parsePatchTenantAccessArgs(args map[string]interface{}) (*pb.PatchTenantAccessRequest, error) {
	raw, ok := args["changes"]
	if !ok {
		return nil, fmt.Errorf("changes is required")
	}
	list, ok := raw.([]interface{})
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("changes must be a non-empty array")
	}
	if len(list) > 32 {
		return nil, fmt.Errorf("at most 32 destination changes per request")
	}
	req := &pb.PatchTenantAccessRequest{}
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("changes[%d] must be an object", i)
		}
		add, err := tenantAccessSources(m, "add_sources")
		if err != nil {
			return nil, fmt.Errorf("changes[%d]: %w", i, err)
		}
		remove, err := tenantAccessSources(m, "remove_sources")
		if err != nil {
			return nil, fmt.Errorf("changes[%d]: %w", i, err)
		}
		ch := &pb.TenantAccessChange{
			Destination:      strings.TrimSpace(getStringArg(m, "destination", "")),
			ExpectedRevision: getStringArg(m, "expected_revision", ""),
			AddSources:       add,
			RemoveSources:    remove,
		}
		if ch.Destination == "" {
			return nil, fmt.Errorf("changes[%d].destination is required", i)
		}
		if ch.ExpectedRevision == "" {
			return nil, fmt.Errorf("changes[%d].expected_revision is required (\"absent\" when no policy exists)", i)
		}
		req.Changes = append(req.Changes, ch)
	}
	return req, nil
}

// tenantAccessSources validates the complete list before any backend call.
func tenantAccessSources(args map[string]interface{}, key string) ([]string, error) {
	raw, present := args[key]
	if !present {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		source, ok := item.(string)
		if !ok || strings.TrimSpace(source) == "" {
			return nil, fmt.Errorf("%s must contain only non-empty strings", key)
		}
		out = append(out, source)
	}
	return out, nil
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
			var req *pb.PatchTenantAccessRequest
			req, err = parsePatchTenantAccessArgs(args)
			if err == nil {
				out, err = client.PatchTenantAccess(req)
			}
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
		"destination": map[string]interface{}{"type": "string", "description": "Destination policy whose ingress is edited"}, "expected_revision": map[string]interface{}{"type": "string", "description": "Observed whole-policy SHA256 or \"absent\""},
		"add_sources":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		"remove_sources": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
	}, "required": []string{"destination", "expected_revision"}, "additionalProperties": false}
	return []Tool{

		{Name: "list_network_policies", Description: "Read Tenant network policies. Configured ingress permissions are not TCP test results.", InputSchema: empty, RequiredScope: auth.ScopeNetworkPolicyRead, Handler: tenantNetworkHandler("list")},
		{Name: "get_network_policy", Description: "Read a destination Tenant policy and its full revision for a safe ingress-only edit.", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"tenant": map[string]interface{}{"type": "string", "description": "Destination native network Tenant key"}}, "required": []string{"tenant"}, "additionalProperties": false}, RequiredScope: auth.ScopeNetworkPolicyRead, Handler: tenantNetworkHandler("get")},
		{Name: "patch_tenant_access", Description: "Admin-only atomic ingress-source add/remove with full revision checks. Source A -> destination B changes B.allow_from_tenants. Two changes grant/revoke both directions atomically. Preserves all egress, mode, metadata, preset and deny rules. Tenant-wide access, not port/Box granularity. Does not test TCP.", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"changes": map[string]interface{}{"description": "Revision-checked destination ingress edits; both directions use two changes in one transaction", "type": "array", "items": change, "minItems": 1, "maxItems": 32}}, "required": []string{"changes"}, "additionalProperties": false}, RequiredScope: auth.ScopeNetworkPolicyWrite, Handler: tenantNetworkHandler("patch")},
	}
}
