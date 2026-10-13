// Package sshauthz contains the daemon-side SSH authorization service.
package sshauthz

import (
	"context"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is the contract-only SSH authorization server for #2516. The
// decision engine is intentionally deferred to the follow-up implementation.
type Server struct {
	pb.UnimplementedSSHAuthzServiceServer
}

// NewServer returns the contract stub registered by the daemon.
func NewServer() *Server { return &Server{} }

// Authorize proves the generated contract is wired while making it impossible
// to mistake this first slice for a working authorization decision engine.
func (s *Server) Authorize(context.Context, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	return nil, status.Error(codes.Unimplemented, "SSH authorization decision engine is not implemented")
}
