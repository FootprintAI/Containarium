package server

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// trackerFullProviderFor resolves provider to the complete
// tracker.Provider — the same resolution trackerWriterFor uses, widened
// by one more type assertion since SubmitTrackerChange is the one
// caller that needs OpenChange.
func (s *ContainerServer) trackerFullProviderFor(provider pb.TrackerProvider) (tracker.Provider, error) {
	rp, err := s.trackerProviderFor(provider)
	if err != nil {
		return nil, err
	}
	fp, ok := rp.(tracker.Provider)
	if !ok {
		return nil, fmt.Errorf("provider %v does not support submitting a change", provider)
	}
	return fp, nil
}

// resolveSubmitConn is resolveWriterConn's OpenChange-capable
// counterpart: same resolution (connection binding, store lookup,
// broker credential), returning the full tracker.Provider instead of
// just the write half.
func (s *ContainerServer) resolveSubmitConn(ctx context.Context, username, connectionName string) (tracker.Provider, tracker.Conn, error) {
	if err := enforceConnectionBinding(ctx, connectionName); err != nil {
		return nil, tracker.Conn{}, err
	}
	trackerConn, err := s.trackerStore.Get(ctx, username, connectionName)
	if err != nil {
		return nil, tracker.Conn{}, mapTrackerError(err)
	}
	provider, err := s.trackerFullProviderFor(trackerConn.Provider)
	if err != nil {
		return nil, tracker.Conn{}, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if s.secretsStore == nil {
		return nil, tracker.Conn{}, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	cred, err := s.secretsStore.BrokerCredential(ctx, username, trackerConn.CredentialSecret)
	if err != nil {
		return nil, tracker.Conn{}, status.Errorf(codes.FailedPrecondition, "resolve broker credential: %v", err)
	}
	return provider, tracker.Conn{
		BaseURL:    trackerConn.BaseURL,
		Project:    trackerConn.Project,
		Credential: cred,
	}, nil
}

// SubmitTrackerChange bundles the calling run's committed workspace out
// of its box, pushes it from a fresh temporary bare repository on the
// host (never a credential inside the box — see
// internal/tracker/submit), and opens a change request referencing
// req.Issue.
//
// This slice wires the RPC's full authn/authz and connection
// resolution — the same checks every other tracker write RPC makes —
// so the contract is complete and CI's auth-coverage gate
// (TestEveryRPCHasAuthGuard) passes before the bundle/push/OpenChange
// orchestration exists. That orchestration is a follow-up PR (#1923);
// until it lands, a request that passes every check below still gets
// Unimplemented, never a silent no-op.
func (s *ContainerServer) SubmitTrackerChange(ctx context.Context, req *pb.SubmitTrackerChangeRequest) (*pb.SubmitTrackerChangeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerWrite); err != nil {
		return nil, err
	}
	if s.trackerStore == nil {
		return nil, status.Error(codes.Unavailable, "tracker store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
	if req.Issue <= 0 {
		return nil, status.Error(codes.InvalidArgument, "issue is required")
	}
	if req.Title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}

	if _, _, err := s.resolveSubmitConn(ctx, req.Username, req.Connection); err != nil {
		return nil, err
	}

	return nil, status.Error(codes.Unimplemented, "tracker change submission lands in a follow-up PR (#1923)")
}
