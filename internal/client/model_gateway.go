package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// ModelGatewayService client, both transports (#1726).
//
// The REST paths here are not a second source of truth: they are the
// (google.api.http) mapping in proto/containarium/v1/model_gateway.proto, and
// http_model_gateway_route_test.go pins every one of them against it. A path
// changed in the proto and not here is a failing test, not a runtime 404.
//
// Note the {provider} path segment carries the ENUM'S NAME
// ("GATEWAY_PROVIDER_KAFEIDO"), because that is what grpc-gateway's runtime.Enum
// converter parses — the enum is the contract on the wire too, not a lowercase
// nickname that the daemon would have to re-map.

// modelGatewayTimeout bounds one ModelGatewayService call. The model-list verb
// reaches an upstream provider, so this has to cover a round trip beyond the
// daemon; the gateway's own ListModels deadline is shorter and fires first.
const modelGatewayTimeout = 30 * time.Second

// ModelGatewayAPI is the transport-independent view of ModelGatewayService, so a
// CLI verb can be written once against either transport.
type ModelGatewayAPI interface {
	SetTenantProviderKey(req *pb.SetTenantProviderKeyRequest) (*pb.SetTenantProviderKeyResponse, error)
	DeleteTenantProviderKey(req *pb.DeleteTenantProviderKeyRequest) (*pb.DeleteTenantProviderKeyResponse, error)
	GetTenantProviderKeyStatus(req *pb.GetTenantProviderKeyStatusRequest) (*pb.GetTenantProviderKeyStatusResponse, error)
	MintGatewayToken(req *pb.MintGatewayTokenRequest) (*pb.MintGatewayTokenResponse, error)
	ListGatewayModels(req *pb.ListGatewayModelsRequest) (*pb.ListGatewayModelsResponse, error)
	Close() error
}

// gatewayKeyPath is the REST path for one (key owner, provider) key. The owner is
// escaped because it carries a ':' separator by construction (`org:<id>`), and
// the provider is the enum's name.
func gatewayKeyPath(keyOwner string, provider pb.GatewayProvider) string {
	return "/v1/model-gateway/keys/" + url.PathEscape(keyOwner) + "/" + url.PathEscape(provider.String())
}

// ---------- gRPC ----------

// SetTenantProviderKey stores or rotates one key owner's real upstream provider
// key. Requires the gateway:admin scope.
func (c *GRPCClient) SetTenantProviderKey(req *pb.SetTenantProviderKeyRequest) (*pb.SetTenantProviderKeyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), modelGatewayTimeout)
	defer cancel()
	resp, err := c.modelGatewayClient.SetTenantProviderKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("set tenant provider key: %w", err)
	}
	return resp, nil
}

// DeleteTenantProviderKey removes one key owner's provider key and revokes the
// tokens issued against it. Requires the gateway:admin scope.
func (c *GRPCClient) DeleteTenantProviderKey(req *pb.DeleteTenantProviderKeyRequest) (*pb.DeleteTenantProviderKeyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), modelGatewayTimeout)
	defer cancel()
	resp, err := c.modelGatewayClient.DeleteTenantProviderKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("delete tenant provider key: %w", err)
	}
	return resp, nil
}

// GetTenantProviderKeyStatus reports a key's fingerprint and set_at — never the
// key. Requires the gateway:admin scope.
func (c *GRPCClient) GetTenantProviderKeyStatus(req *pb.GetTenantProviderKeyStatusRequest) (*pb.GetTenantProviderKeyStatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), modelGatewayTimeout)
	defer cancel()
	resp, err := c.modelGatewayClient.GetTenantProviderKeyStatus(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get tenant provider key status: %w", err)
	}
	return resp, nil
}

// MintGatewayToken issues a scoped gateway token for a box the caller owns.
// Requires the gateway:mint scope.
func (c *GRPCClient) MintGatewayToken(req *pb.MintGatewayTokenRequest) (*pb.MintGatewayTokenResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), modelGatewayTimeout)
	defer cancel()
	resp, err := c.modelGatewayClient.MintGatewayToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("mint gateway token: %w", err)
	}
	return resp, nil
}

// ListGatewayModels lists the provider's models through the gateway, on the
// resolved key owner's key. Requires the gateway:mint scope.
func (c *GRPCClient) ListGatewayModels(req *pb.ListGatewayModelsRequest) (*pb.ListGatewayModelsResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), modelGatewayTimeout)
	defer cancel()
	resp, err := c.modelGatewayClient.ListGatewayModels(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list gateway models: %w", err)
	}
	return resp, nil
}

// ---------- REST ----------

// SetTenantProviderKey stores or rotates one key owner's provider key via REST.
func (c *HTTPClient) SetTenantProviderKey(req *pb.SetTenantProviderKeyRequest) (*pb.SetTenantProviderKeyResponse, error) {
	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	out := &pb.SetTenantProviderKeyResponse{}
	if err := c.trackerDoTimeout(modelGatewayTimeout, http.MethodPut,
		gatewayKeyPath(req.GetKeyOwner(), req.GetProvider()), "set tenant provider key", body, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteTenantProviderKey removes one key owner's provider key via REST.
func (c *HTTPClient) DeleteTenantProviderKey(req *pb.DeleteTenantProviderKeyRequest) (*pb.DeleteTenantProviderKeyResponse, error) {
	out := &pb.DeleteTenantProviderKeyResponse{}
	if err := c.trackerDoTimeout(modelGatewayTimeout, http.MethodDelete,
		gatewayKeyPath(req.GetKeyOwner(), req.GetProvider()), "delete tenant provider key", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTenantProviderKeyStatus reads a key's status via REST.
func (c *HTTPClient) GetTenantProviderKeyStatus(req *pb.GetTenantProviderKeyStatusRequest) (*pb.GetTenantProviderKeyStatusResponse, error) {
	out := &pb.GetTenantProviderKeyStatusResponse{}
	if err := c.trackerDoTimeout(modelGatewayTimeout, http.MethodGet,
		gatewayKeyPath(req.GetKeyOwner(), req.GetProvider()), "get tenant provider key status", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// MintGatewayToken mints a gateway token via REST.
func (c *HTTPClient) MintGatewayToken(req *pb.MintGatewayTokenRequest) (*pb.MintGatewayTokenResponse, error) {
	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	out := &pb.MintGatewayTokenResponse{}
	if err := c.trackerDoTimeout(modelGatewayTimeout, http.MethodPost,
		"/v1/model-gateway/tokens", "mint gateway token", body, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListGatewayModels lists a provider's models via REST. `box` rides as a query
// parameter, matching the GET mapping (only {provider} is in the path).
func (c *HTTPClient) ListGatewayModels(req *pb.ListGatewayModelsRequest) (*pb.ListGatewayModelsResponse, error) {
	path := "/v1/model-gateway/" + url.PathEscape(req.GetProvider().String()) + "/models"
	if box := req.GetBox(); box != "" {
		path += "?box=" + url.QueryEscape(box)
	}
	out := &pb.ListGatewayModelsResponse{}
	if err := c.trackerDoTimeout(modelGatewayTimeout, http.MethodGet, path, "list gateway models", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}
