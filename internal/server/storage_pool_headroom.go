package server

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/poolcapacity"
)

// SetPoolHeadroomGuard wires the pool headroom floor (#3128).
func (s *ContainerServer) SetPoolHeadroomGuard(g *poolcapacity.Guard) {
	s.headroom = g
}

// admitPoolHeadroom refuses op on pool ("" = the daemon's default pool) when
// the pool is at or past its floor, as ResourceExhausted.
func (s *ContainerServer) admitPoolHeadroom(pool string, op poolcapacity.Operation) error {
	err := s.headroom.Admit(pool, op)
	var he *poolcapacity.HeadroomError
	if errors.As(err, &he) {
		return status.Error(codes.ResourceExhausted, he.Error())
	}
	return err
}
