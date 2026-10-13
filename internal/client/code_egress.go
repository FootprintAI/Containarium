package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/codeegress"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CodingToolEgressPolicyService client, both transports (#2378). REST paths
// come from codeegress.PolicyPath, the same function the MCP client uses;
// http_code_egress_route_test.go pins them against the proto mapping.

const codeEgressTimeout = 30 * time.Second

// CodeEgressAPI is the transport-independent view of the service.
type CodeEgressAPI interface {
	SetCodingToolEgressPolicy(req *pb.SetCodingToolEgressPolicyRequest) (*pb.SetCodingToolEgressPolicyResponse, error)
	GetCodingToolEgressPolicy(req *pb.GetCodingToolEgressPolicyRequest) (*pb.GetCodingToolEgressPolicyResponse, error)
	DeleteCodingToolEgressPolicy(req *pb.DeleteCodingToolEgressPolicyRequest) (*pb.DeleteCodingToolEgressPolicyResponse, error)
	Close() error
}

// ---------- gRPC ----------

func (c *GRPCClient) codeEgress() pb.CodingToolEgressPolicyServiceClient {
	return pb.NewCodingToolEgressPolicyServiceClient(c.conn)
}

func (c *GRPCClient) SetCodingToolEgressPolicy(req *pb.SetCodingToolEgressPolicyRequest) (*pb.SetCodingToolEgressPolicyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), codeEgressTimeout)
	defer cancel()
	return c.codeEgress().SetCodingToolEgressPolicy(ctx, req)
}

func (c *GRPCClient) GetCodingToolEgressPolicy(req *pb.GetCodingToolEgressPolicyRequest) (*pb.GetCodingToolEgressPolicyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), codeEgressTimeout)
	defer cancel()
	return c.codeEgress().GetCodingToolEgressPolicy(ctx, req)
}

func (c *GRPCClient) DeleteCodingToolEgressPolicy(req *pb.DeleteCodingToolEgressPolicyRequest) (*pb.DeleteCodingToolEgressPolicyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), codeEgressTimeout)
	defer cancel()
	return c.codeEgress().DeleteCodingToolEgressPolicy(ctx, req)
}

// ---------- HTTP ----------

func (c *HTTPClient) SetCodingToolEgressPolicy(req *pb.SetCodingToolEgressPolicyRequest) (*pb.SetCodingToolEgressPolicyResponse, error) {
	// body: "policy" in the mapping — the request body is the policy itself.
	body, err := protojson.Marshal(req.GetPolicy())
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	out := &pb.SetCodingToolEgressPolicyResponse{}
	if err := c.trackerDoTimeout(codeEgressTimeout, http.MethodPut,
		codeegress.PolicyPath(req.GetPolicy().GetTenant()), "set coding-tool egress policy", body, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HTTPClient) GetCodingToolEgressPolicy(req *pb.GetCodingToolEgressPolicyRequest) (*pb.GetCodingToolEgressPolicyResponse, error) {
	out := &pb.GetCodingToolEgressPolicyResponse{}
	if err := c.trackerDoTimeout(codeEgressTimeout, http.MethodGet,
		codeegress.PolicyPath(req.GetTenant()), "get coding-tool egress policy", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HTTPClient) DeleteCodingToolEgressPolicy(req *pb.DeleteCodingToolEgressPolicyRequest) (*pb.DeleteCodingToolEgressPolicyResponse, error) {
	out := &pb.DeleteCodingToolEgressPolicyResponse{}
	if err := c.trackerDoTimeout(codeEgressTimeout, http.MethodDelete,
		codeegress.PolicyPath(req.GetTenant()), "delete coding-tool egress policy", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}
