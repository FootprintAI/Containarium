package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/anonbox"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// BoxBackend exposes the runtime-neutral box backend so sibling services
// (the anonymous-box door) can be built over the same backend the
// container service uses.
func (s *ContainerServer) BoxBackend() box.BoxBackend { return s.boxBackend }

// AnonEnsurer is the slice of anonbox.Manager the server calls. An
// interface so the authz and mapping tests run against a fake.
type AnonEnsurer interface {
	Ensure(ctx context.Context, req anonbox.EnsureRequest) (*anonbox.EnsureResult, error)
}

// AnonLister lists boxes so ListAnonymousBoxes can filter on the
// anon.fingerprint label. Satisfied by any box.BoxBackend.
type AnonLister interface {
	List(ctx context.Context) ([]box.BoxStatus, error)
}

// AnonymousBoxServer implements AnonymousBoxService (#2197, PR B) over
// internal/anonbox. Claim (#2199) and SetAnonymousDoorConfig (#2200) are
// registered so the contract is complete and authz-gated, but return
// Unimplemented until their issues land.
type AnonymousBoxServer struct {
	pb.UnimplementedAnonymousBoxServiceServer
	ensurer AnonEnsurer
	lister  AnonLister
	limits  anonbox.Limits
}

// NewAnonymousBoxServer wires the service over a manager and a lister.
func NewAnonymousBoxServer(ensurer AnonEnsurer, lister AnonLister, limits anonbox.Limits) *AnonymousBoxServer {
	return &AnonymousBoxServer{ensurer: ensurer, lister: lister, limits: limits}
}

// EnsureAnonymousBox — admin or anon:door. The sentinel's door plugin is
// the intended caller: on the REST shim its request signature is accepted
// in place of a JWT and mapped to the anon:door scope (see
// gateway.anonDoorHandler), so this guard sees the same identity either way.
func (s *AnonymousBoxServer) EnsureAnonymousBox(ctx context.Context, req *pb.EnsureAnonymousBoxRequest) (*pb.EnsureAnonymousBoxResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonDoor); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetPublicKey()) == "" {
		return nil, status.Error(codes.InvalidArgument, "public_key is required")
	}
	res, err := s.ensurer.Ensure(ctx, anonbox.EnsureRequest{
		Fingerprint: req.GetFingerprint(),
		PublicKey:   req.GetPublicKey(),
		SourceIP:    req.GetSourceIp(),
	})
	if err != nil {
		return nil, anonErrToStatus(err)
	}
	out := &pb.EnsureAnonymousBoxResponse{
		BoxName:         res.BoxName,
		SshHost:         res.SSHHost,
		SshPort:         int32(res.SSHPort), //nolint:gosec // a port
		SshUser:         res.SSHUser,
		Reused:          res.Reused,
		PreviousExpired: res.PreviousExpired,
	}
	if !res.TTLExpiresAt.IsZero() {
		out.TtlExpiresAt = timestamppb.New(res.TTLExpiresAt)
	}
	return out, nil
}

// ClaimAnonymousBox — admin or anon:admin. Implemented by #2199.
func (s *AnonymousBoxServer) ClaimAnonymousBox(ctx context.Context, _ *pb.ClaimAnonymousBoxRequest) (*pb.ClaimAnonymousBoxResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonAdmin); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "ClaimAnonymousBox lands with #2199")
}

// GetAnonymousDoorConfig — admin or anon:admin. Until #2200 the door has
// no kill switch or bans: enabled, nothing banned, limits echoed.
func (s *AnonymousBoxServer) GetAnonymousDoorConfig(ctx context.Context, _ *pb.GetAnonymousDoorConfigRequest) (*pb.AnonymousDoorConfig, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonAdmin); err != nil {
		return nil, err
	}
	return &pb.AnonymousDoorConfig{
		Enabled: true,
		Limits: &pb.AnonymousBoxLimits{
			Cpu:        s.limits.CPU,
			Memory:     s.limits.Memory,
			Disk:       s.limits.Disk,
			TtlSeconds: int64(s.limits.TTL / time.Second),
		},
	}, nil
}

// SetAnonymousDoorConfig — admin or anon:admin. Implemented by #2200.
func (s *AnonymousBoxServer) SetAnonymousDoorConfig(ctx context.Context, _ *pb.SetAnonymousDoorConfigRequest) (*pb.AnonymousDoorConfig, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonAdmin); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "SetAnonymousDoorConfig lands with #2200")
}

// ListAnonymousBoxes — admin or anon:admin. Every box carrying the
// anon.fingerprint label; the raw fingerprint and key never leave.
func (s *AnonymousBoxServer) ListAnonymousBoxes(ctx context.Context, _ *pb.ListAnonymousBoxesRequest) (*pb.ListAnonymousBoxesResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonAdmin); err != nil {
		return nil, err
	}
	all, err := s.lister.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list boxes: %v", err)
	}
	out := &pb.ListAnonymousBoxesResponse{}
	for _, b := range all {
		if b.Labels[anonbox.LabelFingerprint] == "" {
			continue
		}
		ab := &pb.AnonymousBox{
			BoxName:         b.Ref.Name,
			FingerprintHash: b.Labels[anonbox.LabelFPHash],
			SshHost:         b.IPAddress,
			Claimed:         b.Labels[anonbox.LabelClaimedAt] != "",
		}
		if t, err := time.Parse(time.RFC3339, b.Labels[anonbox.LabelCreatedAt]); err == nil {
			ab.CreatedAt = timestamppb.New(t)
		}
		if !b.TTLExpiresAt.IsZero() {
			ab.TtlExpiresAt = timestamppb.New(b.TTLExpiresAt)
		}
		out.Boxes = append(out.Boxes, ab)
	}
	return out, nil
}

// anonErrToStatus maps manager errors onto gRPC codes: a bad key or a
// fingerprint that does not match it is the caller's fault; anything
// else (create, ACL, guest files) is the daemon's.
func anonErrToStatus(err error) error {
	var invalid anonbox.InvalidRequestError
	if errors.As(err, &invalid) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Errorf(codes.Internal, "%v", err)
}
