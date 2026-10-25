package mcp

import (
	"encoding/json"
	"fmt"
)

type networkTenantCapabilitiesAPI interface {
	GetNetworkTenantCapabilities() (*NetworkTenantCapabilities, error)
}
type NetworkTenantCapabilities struct {
	Contract             string `json:"contract"`
	NativeMembershipRead bool   `json:"nativeMembershipRead"`
	SharedTenantCreate   bool   `json:"sharedTenantCreate"`
	AtomicTenantAccess   bool   `json:"atomicTenantAccess"`
	NetworkPolicyWrite   bool   `json:"networkPolicyWrite"`
	Reason               string `json:"reason"`
	BackendScope         string `json:"backendScope"`
}

func (c *Client) GetNetworkTenantCapabilities() (*NetworkTenantCapabilities, error) {
	var out NetworkTenantCapabilities
	data, err := c.doRequest("GET", "/v1/network-tenants/capabilities", nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func networkTenantCapabilityTool() Tool {
	return Tool{Name: "network_tenant_capabilities", Description: "Read authenticated local native network Tenant capability. Shared creation and atomic cross-Tenant policy writes are independent.", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}, Handler: func(c API, _ map[string]interface{}) (string, error) {
		api, ok := c.(networkTenantCapabilitiesAPI)
		if !ok {
			return "", fmt.Errorf("network Tenant capability query unavailable")
		}
		out, err := api.GetNetworkTenantCapabilities()
		if err != nil {
			return "", err
		}
		data, err := json.MarshalIndent(out, "", "  ")
		return string(data), err
	}}
}
