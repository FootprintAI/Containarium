package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// networkTenantSourceFromProto maps the wire enum to the provider-source
// string. The UNSPECIFIED zero value becomes "" so an old daemon (which never
// sets the field) and the HTTP client (which omits absent fields) agree, and
// `containarium get` does not print a tenant line for every un-tenanted box.
func networkTenantSourceFromProto(s pb.NetworkTenantSource) incus.NetworkTenantSource {
	if s == pb.NetworkTenantSource_NETWORK_TENANT_SOURCE_UNSPECIFIED {
		return ""
	}
	return incus.NetworkTenantSource(s.String())
}

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
	// DiscardUnknown: a newer daemon may add capability fields; the handshake
	// exists to tolerate newer providers, not to refuse every explicit create
	// until this client is rebuilt.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

func requireNativeTenantCapability(out *pb.GetNetworkTenantCapabilitiesResponse) error {
	if out.GetContract() != incus.NativeTenantContractID || out.GetBackendScope() != incus.NativeTenantBackendScope || !out.GetNativeMembershipRead() || !out.GetSharedTenantCreate() {
		return fmt.Errorf("provider does not advertise ready native network Tenant creation")
	}
	return nil
}

// ErrNetworkPolicyAbsent reports that no policy exists for the destination —
// the typed shape of the REST read's 404, so callers can preview an
// absent-policy revoke instead of failing.
var ErrNetworkPolicyAbsent = fmt.Errorf("no network policy for tenant")

// GetNetworkPolicy reads one stored policy with its whole-policy revision —
// the typed counterpart of the REST GET /v1/network-policies/{tenant}.
// A missing policy returns ErrNetworkPolicyAbsent.
func (c *GRPCClient) GetNetworkPolicy(tenant string) (*pb.GetNetworkPolicyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := c.networkPolicyClient.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: tenant})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrNetworkPolicyAbsent
		}
		return nil, err
	}
	return out, nil
}
func (c *HTTPClient) GetNetworkPolicy(tenant string) (*pb.GetNetworkPolicyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.doRequest(ctx, http.MethodGet, "/v1/network-policies/"+url.PathEscape(tenant), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNetworkPolicyAbsent
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network policy read status %d", resp.StatusCode)
	}
	out := &pb.GetNetworkPolicyResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

// PatchTenantAccess applies revision-checked atomic ingress edits — the typed
// counterpart of POST /v1/network-policies/tenant-access.
func (c *GRPCClient) PatchTenantAccess(req *pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return c.networkPolicyClient.PatchTenantAccess(ctx, req)
}
func (c *HTTPClient) PatchTenantAccess(req *pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	raw, err := protojson.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/network-policies/tenant-access", raw)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tenant access patch status %d: %s", resp.StatusCode, fmt.Sprintf("%s", body[:min(len(body), 512)]))
	}
	out := &pb.PatchTenantAccessResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, out); err != nil {
		return nil, err
	}
	return out, nil
}
