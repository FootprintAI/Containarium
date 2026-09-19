package server

import (
	"context"
	"errors"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// resolveReaderConn resolves a named connection to its ReaderProvider
// adapter and a ready-to-use tracker.Conn (base URL, project, and the
// resolved broker credential) — the shared setup GetTrackerIssue,
// ListTrackerIssues, and GetTrackerChange all need before calling into
// an adapter.
//
// Tenant scoping and the tracker:read scope are the caller's
// responsibility (checked before this is called). This also enforces the
// run <-> connection JWT-claim binding (#1922 step 6): a run token bound
// to a different connection is rejected before the store is even
// consulted, so it can't distinguish "wrong connection" from "no such
// connection" for one it's not bound to.
func (s *ContainerServer) resolveReaderConn(ctx context.Context, username, connectionName string) (tracker.ReaderProvider, tracker.Conn, error) {
	if err := enforceConnectionBinding(ctx, connectionName); err != nil {
		return nil, tracker.Conn{}, err
	}
	trackerConn, err := s.trackerStore.Get(ctx, username, connectionName)
	if err != nil {
		return nil, tracker.Conn{}, mapTrackerError(err)
	}
	provider, err := s.trackerProviderFor(trackerConn.Provider)
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

// GetTrackerIssue reads a single issue, including its comments.
func (s *ContainerServer) GetTrackerIssue(ctx context.Context, req *pb.GetTrackerIssueRequest) (*pb.GetTrackerIssueResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerRead); err != nil {
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

	provider, conn, err := s.resolveReaderConn(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, err
	}

	issue, err := provider.GetIssue(ctx, conn, req.Number)
	if err != nil {
		return nil, mapProviderError(err)
	}
	return &pb.GetTrackerIssueResponse{Issue: toProtoIssue(issue)}, nil
}

// ListTrackerIssues enumerates issues, optionally filtered.
func (s *ContainerServer) ListTrackerIssues(ctx context.Context, req *pb.ListTrackerIssuesRequest) (*pb.ListTrackerIssuesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerRead); err != nil {
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

	provider, conn, err := s.resolveReaderConn(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, err
	}

	issues, err := provider.ListIssues(ctx, conn, tracker.IssueFilter{
		State:  req.State,
		Labels: req.Labels,
		Search: req.Search,
	})
	if err != nil {
		return nil, mapProviderError(err)
	}
	out := make([]*pb.TrackerIssue, 0, len(issues))
	for _, i := range issues {
		out = append(out, toProtoIssue(i))
	}
	return &pb.ListTrackerIssuesResponse{Issues: out}, nil
}

// GetTrackerChange reads a single change request's state and CI
// verdict.
func (s *ContainerServer) GetTrackerChange(ctx context.Context, req *pb.GetTrackerChangeRequest) (*pb.GetTrackerChangeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerRead); err != nil {
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

	provider, conn, err := s.resolveReaderConn(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, err
	}

	change, err := provider.GetChange(ctx, conn, req.Number)
	if err != nil {
		return nil, mapProviderError(err)
	}
	return &pb.GetTrackerChangeResponse{Change: toProtoChange(change)}, nil
}

// mapProviderError maps a tracker.Provider adapter's sentinel errors to
// gRPC status codes.
func mapProviderError(err error) error {
	switch {
	case errors.Is(err, tracker.ErrNotFound):
		return status.Error(codes.NotFound, "not found on tracker")
	case errors.Is(err, tracker.ErrCredentialInvalid):
		return status.Errorf(codes.FailedPrecondition, "credential rejected by tracker: %v", err)
	case errors.Is(err, tracker.ErrUnreachable):
		return status.Errorf(codes.Unavailable, "tracker unreachable: %v", err)
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

func toProtoComment(c tracker.Comment) *pb.TrackerComment {
	return &pb.TrackerComment{
		Author:    c.Author,
		CreatedAt: timestamppb.New(c.CreatedAt),
		Body:      c.Body,
	}
}

func toProtoIssue(i tracker.Issue) *pb.TrackerIssue {
	comments := make([]*pb.TrackerComment, 0, len(i.Comments))
	for _, c := range i.Comments {
		comments = append(comments, toProtoComment(c))
	}
	return &pb.TrackerIssue{
		Number:   i.Number,
		Title:    i.Title,
		Body:     i.Body,
		State:    i.State,
		Labels:   i.Labels,
		Assignee: i.Assignee,
		Comments: comments,
	}
}

func toProtoChange(c tracker.Change) *pb.TrackerChange {
	return &pb.TrackerChange{
		Number:    c.Number,
		State:     c.State,
		CiVerdict: c.CIVerdict,
		Url:       c.URL,
	}
}
