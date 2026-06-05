package server

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// KmsServer implements the gRPC KmsService — read-only KMS status,
// envelope coverage, and the legacy→envelope migration trigger. It
// is a thin adapter over the same secrets Store the SecretsService
// uses; it deliberately does NOT configure backends (that stays in
// CONTAINARIUM_KMS_BACKEND + per-backend env, an operator concern).
//
// It holds the ContainerServer rather than the Store directly so it
// reads the live `secretsStore` field (wired after Postgres + the
// master key resolve) and the startup KMS-status snapshot.
type KmsServer struct {
	pb.UnimplementedKmsServiceServer
	containers *ContainerServer
}

// NewKmsServer wires the KMS admin service to the container server.
func NewKmsServer(containers *ContainerServer) *KmsServer {
	return &KmsServer{containers: containers}
}

// SetKMSStatus records the boot-time KMS configuration for the
// GetKMSStatus RPC. backend is the raw CONTAINARIUM_KMS_BACKEND value
// (normalized here); configured is true when a real KMS client was
// built (backend != none and no config error).
func (s *ContainerServer) SetKMSStatus(backend, description string, configured, requireEnvelope bool) {
	b := strings.ToLower(strings.TrimSpace(backend))
	if b == "" {
		b = "none"
	}
	s.kmsBackend = b
	s.kmsDescription = description
	s.kmsConfigured = configured
	s.requireEnvelope = requireEnvelope
}

// requireKMSAdmin gates every KmsService RPC: the kms:admin scope
// AND the admin role. These operations are platform-wide (not
// tenant-scoped), so there is no AuthorizeTenant call — admin is the
// authorization.
func requireKMSAdmin(ctx context.Context) error {
	if err := auth.RequireScope(ctx, auth.ScopeKMSAdmin); err != nil {
		return err
	}
	_, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	if !auth.HasRole(roles, auth.RoleAdmin) {
		return status.Error(codes.PermissionDenied, "admin role required for KMS administration")
	}
	return nil
}

// GetKMSStatus reports the active backend and the envelope-retirement
// gate. No store dependency — answers even on a --standalone daemon
// (backend=none).
func (s *KmsServer) GetKMSStatus(ctx context.Context, _ *pb.GetKMSStatusRequest) (*pb.GetKMSStatusResponse, error) {
	if err := requireKMSAdmin(ctx); err != nil {
		return nil, err
	}
	c := s.containers
	backend := c.kmsBackend
	if backend == "" {
		backend = "none"
	}
	return &pb.GetKMSStatusResponse{
		Backend:         backend,
		Description:     c.kmsDescription,
		KmsConfigured:   c.kmsConfigured,
		RequireEnvelope: c.requireEnvelope,
	}, nil
}

// GetEnvelopeCoverage counts stored secrets by encryption mode.
func (s *KmsServer) GetEnvelopeCoverage(ctx context.Context, _ *pb.GetEnvelopeCoverageRequest) (*pb.GetEnvelopeCoverageResponse, error) {
	if err := requireKMSAdmin(ctx); err != nil {
		return nil, err
	}
	if s.containers.secretsStore == nil {
		return nil, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	cov, err := s.containers.secretsStore.VerifyEnvelopeCoverage(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "coverage: %v", err)
	}
	return &pb.GetEnvelopeCoverageResponse{
		Total:    int64(cov.Total),
		Legacy:   int64(cov.Legacy),
		Envelope: int64(cov.Envelope),
	}, nil
}

// MigrateToEnvelope re-wraps legacy rows under the active KMS KEK.
// FailedPrecondition when no KMS backend is configured (there is
// nothing to migrate to).
func (s *KmsServer) MigrateToEnvelope(ctx context.Context, req *pb.MigrateToEnvelopeRequest) (*pb.MigrateToEnvelopeResponse, error) {
	if err := requireKMSAdmin(ctx); err != nil {
		return nil, err
	}
	if s.containers.secretsStore == nil {
		return nil, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	res, err := s.containers.secretsStore.MigrateLegacyToEnvelope(ctx, secrets.MigrateOptions{
		BatchSize: int(req.BatchSize),
		MaxRows:   int(req.MaxRows),
		DryRun:    req.DryRun,
	})
	if err != nil {
		if errors.Is(err, secrets.ErrMigrateNoKMS) {
			return nil, status.Error(codes.FailedPrecondition,
				"no KMS backend configured; set CONTAINARIUM_KMS_BACKEND before migrating")
		}
		return nil, status.Errorf(codes.Internal, "migrate: %v", err)
	}

	mode := "MIGRATE"
	if req.DryRun {
		mode = "DRY-RUN"
	}
	log.Printf("[kms] %s scanned=%d migrated=%d already=%d failed=%d",
		mode, res.Scanned, res.Migrated, res.AlreadyDone, res.Failed)

	out := &pb.MigrateToEnvelopeResponse{
		Scanned:     int64(res.Scanned),
		Migrated:    int64(res.Migrated),
		AlreadyDone: int64(res.AlreadyDone),
		Failed:      int64(res.Failed),
		DryRun:      req.DryRun,
	}
	for _, e := range res.Errors {
		out.Errors = append(out.Errors, &pb.MigrateRowError{
			Username: e.Username,
			Name:     e.Name,
			Error:    e.Err,
		})
	}
	return out, nil
}
