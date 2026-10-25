package client

import (
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"net/http"
	"time"
)

func (c *GRPCClient) GetNetworkTenantCapabilities() (*pb.GetNetworkTenantCapabilitiesResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.networkClient.GetNetworkTenantCapabilities(ctx, &pb.GetNetworkTenantCapabilitiesRequest{})
}
func (c *HTTPClient) GetNetworkTenantCapabilities() (*pb.GetNetworkTenantCapabilitiesResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.doRequest(ctx, http.MethodGet, "/v1/network-tenants/capabilities", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network Tenant capability status %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := &pb.GetNetworkTenantCapabilitiesResponse{}
	if err := protojson.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

func requireNativeTenantCapability(out *pb.GetNetworkTenantCapabilitiesResponse) error {
	if out.GetContract() != "boxweave.tenant-network/v1" || out.GetBackendScope() != "local-lxc" || !out.GetNativeMembershipRead() || !out.GetSharedTenantCreate() {
		return fmt.Errorf("provider does not advertise ready native network Tenant creation")
	}
	return nil
}
