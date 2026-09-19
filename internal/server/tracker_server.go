package server

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetTrackerStore wires the tracker-connections backend onto the server.
// Called from dual_server.go after the Postgres connection has been
// resolved. Nil store keeps the TrackerService RPCs returning
// Unavailable (--standalone daemons), same convention as
// SetSecretsStore.
func (s *ContainerServer) SetTrackerStore(store *tracker.Store) {
	s.trackerStore = store
}

// SetTrackerConnection creates or updates a tracker connection.
// Connection CRUD is gated by tracker:admin (NOT tracker:read/write,
// which are what an agent's run-scoped JWT carries for the tracker
// verbs themselves, #1922) — naming where a tracker is and which
// credential to trust is an operator decision.
func (s *ContainerServer) SetTrackerConnection(ctx context.Context, req *pb.SetTrackerConnectionRequest) (*pb.SetTrackerConnectionResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerAdmin); err != nil {
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

	if err := s.requireBrokerOnlySecret(ctx, req.Username, req.CredentialSecret); err != nil {
		return nil, err
	}

	conn, err := s.trackerStore.Set(ctx, tracker.Connection{
		Username:         req.Username,
		Name:             req.Name,
		Provider:         req.Provider,
		BaseURL:          req.BaseUrl,
		Project:          req.Project,
		CredentialSecret: req.CredentialSecret,
	})
	if err != nil {
		return nil, mapTrackerError(err)
	}

	log.Printf("[tracker] connection set %s/%s provider=%s project=%s", req.Username, req.Name, req.Provider, req.Project)

	msg := "connection created"
	if !conn.CreatedAt.Equal(conn.UpdatedAt) {
		msg = "connection updated"
	}
	return &pb.SetTrackerConnectionResponse{
		Message:    msg,
		Connection: toProtoTrackerConnection(conn),
	}, nil
}

// GetTrackerConnection returns a single named connection's metadata.
// Never returns the credential value — TrackerConnection only ever
// carries the secret's name.
func (s *ContainerServer) GetTrackerConnection(ctx context.Context, req *pb.GetTrackerConnectionRequest) (*pb.GetTrackerConnectionResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerAdmin); err != nil {
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

	conn, err := s.trackerStore.Get(ctx, req.Username, req.Name)
	if err != nil {
		return nil, mapTrackerError(err)
	}
	return &pb.GetTrackerConnectionResponse{Connection: toProtoTrackerConnection(conn)}, nil
}

// ListTrackerConnections returns every connection a tenant owns.
func (s *ContainerServer) ListTrackerConnections(ctx context.Context, req *pb.ListTrackerConnectionsRequest) (*pb.ListTrackerConnectionsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerAdmin); err != nil {
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

	list, err := s.trackerStore.List(ctx, req.Username)
	if err != nil {
		return nil, mapTrackerError(err)
	}
	out := make([]*pb.TrackerConnection, 0, len(list))
	for i := range list {
		out = append(out, toProtoTrackerConnection(&list[i]))
	}
	return &pb.ListTrackerConnectionsResponse{Connections: out}, nil
}

// DeleteTrackerConnection removes a named connection. Does not delete
// the underlying credential secret.
func (s *ContainerServer) DeleteTrackerConnection(ctx context.Context, req *pb.DeleteTrackerConnectionRequest) (*pb.DeleteTrackerConnectionResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerAdmin); err != nil {
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

	if err := s.trackerStore.Delete(ctx, req.Username, req.Name); err != nil {
		return nil, mapTrackerError(err)
	}
	log.Printf("[tracker] connection deleted %s/%s", req.Username, req.Name)
	return &pb.DeleteTrackerConnectionResponse{
		Message: fmt.Sprintf("connection %s deleted", req.Name),
	}, nil
}

// requireBrokerOnlySecret validates that secretName is a secret owned by
// username, in SECRET_DELIVERY_BROKER_ONLY mode. Reuses
// secrets.Store.Get's existing three-way outcome rather than adding a
// new store method: ErrBrokerOnly means the row exists and is
// broker-only (allowed); a nil error means it exists but is a
// delivering mode (rejected — a tracker connection must never point at
// a secret a box can also read); ErrNotFound means no such secret for
// this tenant.
func (s *ContainerServer) requireBrokerOnlySecret(ctx context.Context, username, secretName string) error {
	if secretName == "" {
		return status.Error(codes.InvalidArgument, "credential_secret is required")
	}
	if s.secretsStore == nil {
		return status.Error(codes.FailedPrecondition, "secrets store not configured on this daemon; a tracker connection needs a broker-only secret to reference")
	}
	_, _, err := s.secretsStore.Get(ctx, username, secretName)
	switch {
	case errors.Is(err, secrets.ErrBrokerOnly):
		return nil
	case err == nil:
		return status.Errorf(codes.InvalidArgument,
			"credential_secret %q is not in broker-only mode; set it with delivery_mode=SECRET_DELIVERY_BROKER_ONLY first", secretName)
	case errors.Is(err, secrets.ErrNotFound):
		return status.Errorf(codes.InvalidArgument, "credential_secret %q not found for tenant %q", secretName, username)
	default:
		return status.Errorf(codes.Internal, "check credential_secret: %v", err)
	}
}

// mapTrackerError maps tracker store errors to gRPC status codes.
func mapTrackerError(err error) error {
	if errors.Is(err, tracker.ErrNotFound) {
		return status.Error(codes.NotFound, "tracker connection not found")
	}
	msg := err.Error()
	if isValidationError(msg) || isTrackerValidationError(msg) {
		return status.Error(codes.InvalidArgument, msg)
	}
	return status.Errorf(codes.Internal, "%v", err)
}

// isTrackerValidationError matches internal/tracker's own plain-string
// validation errors (username / name / project / credential_secret
// required, unknown provider) — a small, stable set, same cheap
// substring-match idiom as secrets_server.go's isValidationError.
func isTrackerValidationError(msg string) bool {
	keywords := []string{
		"username is required",
		"name is required",
		"project is required",
		"credential_secret is required",
		"provider must be",
	}
	for _, kw := range keywords {
		if containsCI(msg, kw) {
			return true
		}
	}
	return false
}

// toProtoTrackerConnection converts the storage-layer struct to the
// proto-facing one. credential_expires_at is left unset — populated
// starting in #1921 step 3 (DescribeCredential).
func toProtoTrackerConnection(c *tracker.Connection) *pb.TrackerConnection {
	if c == nil {
		return nil
	}
	return &pb.TrackerConnection{
		Username:         c.Username,
		Name:             c.Name,
		Provider:         c.Provider,
		BaseUrl:          c.BaseURL,
		Project:          c.Project,
		CredentialSecret: c.CredentialSecret,
	}
}
