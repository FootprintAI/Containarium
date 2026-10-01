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

// AnonClaimer is the slice of anonbox.Manager that redeems a claim token.
type AnonClaimer interface {
	Claim(ctx context.Context, req anonbox.ClaimRequest) (*anonbox.ClaimResult, error)
}

// AnonDoor is the operator state slice of anonbox.Manager (#2200).
type AnonDoor interface {
	DoorConfig() anonbox.DoorConfig
	SetDoorConfig(anonbox.DoorConfig) error
	DoorErr() error
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
	claimer AnonClaimer // nil = claims not enabled on this daemon
	door    AnonDoor    // nil = no kill switch / bans (always open)
	limits  anonbox.Limits
}

// SetDoor enables Get/SetAnonymousDoorConfig over the manager's door
// state (#2200).
func (s *AnonymousBoxServer) SetDoor(d AnonDoor) { s.door = d }

// SetClaimer enables ClaimAnonymousBox (#2199). Without it the RPC is
// gated but Unimplemented — a daemon without a claim secret cannot
// verify a token.
func (s *AnonymousBoxServer) SetClaimer(c AnonClaimer) { s.claimer = c }

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

// ClaimAnonymousBox — admin or anon:admin (the cloud control plane after
// signup, or an operator via `containarium anon claim`). Redeems the
// single-use token and binds the box to the tenant (#2199).
func (s *AnonymousBoxServer) ClaimAnonymousBox(ctx context.Context, req *pb.ClaimAnonymousBoxRequest) (*pb.ClaimAnonymousBoxResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonAdmin); err != nil {
		return nil, err
	}
	if s.claimer == nil {
		return nil, status.Error(codes.Unimplemented, "claims are not enabled on this daemon")
	}
	if strings.TrimSpace(req.GetClaimToken()) == "" || strings.TrimSpace(req.GetTenant()) == "" {
		return nil, status.Error(codes.InvalidArgument, "claim_token and tenant are required")
	}
	res, err := s.claimer.Claim(ctx, anonbox.ClaimRequest{
		Token:          strings.TrimSpace(req.GetClaimToken()),
		Tenant:         strings.TrimSpace(req.GetTenant()),
		AuthorizedKeys: req.GetAuthorizedKeys(),
	})
	if err != nil {
		return nil, claimErrToStatus(err)
	}
	return &pb.ClaimAnonymousBoxResponse{BoxName: res.BoxName, Tenant: res.Tenant}, nil
}

// claimErrToStatus: the design's codes — second redeem AlreadyExists,
// expired FailedPrecondition, bad signature/malformed/mismatch
// PermissionDenied, box gone NotFound, caller fault InvalidArgument.
func claimErrToStatus(err error) error {
	var invalid anonbox.InvalidRequestError
	switch {
	case errors.Is(err, anonbox.ErrClaimAlreadyClaimed):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, anonbox.ErrClaimExpired):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, anonbox.ErrClaimInvalid):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, anonbox.ErrClaimNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &invalid):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

// GetAnonymousDoorConfig — admin or anon:admin. The door's operator state
// (kill switch, message, bans) plus the daemon's fixed limits.
func (s *AnonymousBoxServer) GetAnonymousDoorConfig(ctx context.Context, _ *pb.GetAnonymousDoorConfigRequest) (*pb.AnonymousDoorConfig, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonAdmin); err != nil {
		return nil, err
	}
	return s.doorConfigProto(), nil
}

// SetAnonymousDoorConfig — admin or anon:admin. Replaces enabled /
// disabled_message / banned_fingerprints; limits are read-only (daemon
// flags) and ignored on input.
func (s *AnonymousBoxServer) SetAnonymousDoorConfig(ctx context.Context, req *pb.SetAnonymousDoorConfigRequest) (*pb.AnonymousDoorConfig, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAnonAdmin); err != nil {
		return nil, err
	}
	if s.door == nil {
		return nil, status.Error(codes.Unimplemented, "the anonymous door has no operator state on this daemon")
	}
	cfg := req.GetConfig()
	if cfg == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}
	if err := s.door.SetDoorConfig(anonbox.DoorConfig{
		Enabled:            cfg.GetEnabled(),
		DisabledMessage:    cfg.GetDisabledMessage(),
		BannedFingerprints: cfg.GetBannedFingerprints(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "persist door config: %v", err)
	}
	return s.doorConfigProto(), nil
}

func (s *AnonymousBoxServer) doorConfigProto() *pb.AnonymousDoorConfig {
	out := &pb.AnonymousDoorConfig{
		Enabled: true,
		Limits: &pb.AnonymousBoxLimits{
			Cpu:                 s.limits.CPU,
			Memory:              s.limits.Memory,
			Disk:                s.limits.Disk,
			TtlSeconds:          int64(s.limits.TTL / time.Second),
			MaxBoxes:            int32(s.limits.MaxBoxes), //nolint:gosec // a small cap
			PerFingerprintRps:   s.limits.PerKeyPerMinute / 60,
			PerFingerprintBurst: int32(s.limits.PerKeyBurst), //nolint:gosec // a small burst
			PerIpRps:            s.limits.PerIPPerMinute / 60,
			PerIpBurst:          int32(s.limits.PerIPBurst), //nolint:gosec // a small burst
		},
	}
	if s.door != nil {
		d := s.door.DoorConfig()
		out.Enabled = d.Enabled
		out.DisabledMessage = d.DisabledMessage
		out.BannedFingerprints = d.BannedFingerprints
	}
	return out
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
// fingerprint that does not match it is the caller's fault; a closed
// door, a ban, a rate limit or the cap are the daemon saying no (#2200);
// anything else (create, ACL, guest files) is the daemon's fault.
func anonErrToStatus(err error) error {
	var invalid anonbox.InvalidRequestError
	var closed anonbox.DoorClosedError
	switch {
	case errors.As(err, &invalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &closed):
		return status.Error(codes.FailedPrecondition, strings.TrimPrefix(err.Error(), "anonbox: "))
	case errors.Is(err, anonbox.ErrBanned):
		return status.Error(codes.PermissionDenied, strings.TrimPrefix(err.Error(), "anonbox: "))
	case errors.Is(err, anonbox.ErrRateLimited), errors.Is(err, anonbox.ErrAtCapacity):
		return status.Error(codes.ResourceExhausted, strings.TrimPrefix(err.Error(), "anonbox: "))
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

// AnonRouteGuard builds the check AddRoute / AddPassthroughRoute run on
// their target box (#2200): an anonymous box nobody has claimed may not
// expose anything. getLabels is the daemon's label reader. A lookup
// failure falls back to the name — an anonymous box is always
// "anon-<fp8>-container" — so a transient Incus error cannot open a hole,
// and a normal box is never blocked by one.
func AnonRouteGuard(getLabels func(containerName string) (map[string]string, error)) func(containerName string) error {
	return func(name string) error {
		if name == "" {
			return nil
		}
		labels, err := getLabels(name)
		if err != nil {
			if strings.HasPrefix(name, "anon-") {
				return status.Errorf(codes.FailedPrecondition, "%s looks like an anonymous box and its state could not be read (%v): claim it first", name, err)
			}
			return nil
		}
		if anonbox.IsUnclaimedAnonymous(labels) {
			return status.Errorf(codes.FailedPrecondition, "%s is an unclaimed anonymous box: no public ports or routes until it is claimed (containarium claim)", name)
		}
		return nil
	}
}
