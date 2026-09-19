package server

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/internal/tracker"
	trackergithub "github.com/footprintai/containarium/internal/tracker/github"
	trackergitlab "github.com/footprintai/containarium/internal/tracker/gitlab"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SetTrackerStore wires the tracker-connections backend onto the server.
// Called from dual_server.go after the Postgres connection has been
// resolved. Nil store keeps the TrackerService RPCs returning
// Unavailable (--standalone daemons), same convention as
// SetSecretsStore.
func (s *ContainerServer) SetTrackerStore(store *tracker.Store) {
	s.trackerStore = store
}

// SetRunRegistry wires the shared in-memory run registry (#1922) — the
// SAME instance dual_server.go gives to AgentSkillServer, so a run's
// skill/model (for the identity stamp) and liveness (for
// ClaimTrackerIssue) can be resolved without a database round trip.
func (s *ContainerServer) SetRunRegistry(r *runlease.Registry) {
	s.runRegistry = r
}

// SetClaimLocks wires the shared ClaimLocks used to serialize
// ClaimTrackerIssue calls within this daemon process.
func (s *ContainerServer) SetClaimLocks(l *tracker.ClaimLocks) {
	s.claimLocks = l
}

// SetTrackerDescribers overrides the provider -> ReaderProvider
// registry. Production wiring never calls this — trackerProviderFor
// constructs the real GitHub/GitLab adapters per call when the field is
// nil, the same "cheap to construct, no shared mutable state" idiom as
// boxes() falling back to boxlxc.New(s.manager). Tests use this to
// substitute fakes.
//
// Named for #1921 (DescribeCredential only); the parameter type widened
// to tracker.ReaderProvider in #1922 when GetIssue/ListIssues/GetChange
// needed the same per-provider resolution — every existing caller only
// used DescribeCredential and keeps compiling unchanged, since
// ReaderProvider embeds CredentialDescriber.
func (s *ContainerServer) SetTrackerDescribers(m map[pb.TrackerProvider]tracker.ReaderProvider) {
	s.trackerDescribers = m
}

// trackerProviderFor resolves the ReaderProvider for provider.
func (s *ContainerServer) trackerProviderFor(provider pb.TrackerProvider) (tracker.ReaderProvider, error) {
	if s.trackerDescribers != nil {
		d, ok := s.trackerDescribers[provider]
		if !ok {
			return nil, fmt.Errorf("no reader provider registered for provider %v", provider)
		}
		return d, nil
	}
	switch provider {
	case pb.TrackerProvider_TRACKER_PROVIDER_GITHUB:
		return trackergithub.New(nil), nil
	case pb.TrackerProvider_TRACKER_PROVIDER_GITLAB:
		return trackergitlab.New(nil), nil
	default:
		return nil, fmt.Errorf("no reader provider for provider %v", provider)
	}
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

	// Best-effort: an operator may be registering a connection before
	// the tracker is reachable from the daemon's network, or before the
	// token is fully propagated upstream. A describe failure here must
	// never fail the connection write itself — see
	// describeCredentialBestEffort's own doc comment.
	s.describeCredentialBestEffort(ctx, conn)

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

// GetTrackerStatus probes a connection's credential live, against the
// tracker itself — reachability, validity, scopes, expiry, and breadth
// versus the provider's preferred credential type.
func (s *ContainerServer) GetTrackerStatus(ctx context.Context, req *pb.GetTrackerStatusRequest) (*pb.GetTrackerStatusResponse, error) {
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
	resp := &pb.GetTrackerStatusResponse{Connection: toProtoTrackerConnection(conn)}

	describer, derr := s.trackerProviderFor(conn.Provider)
	if derr != nil {
		resp.Detail = derr.Error()
		return resp, nil
	}
	if s.secretsStore == nil {
		resp.Detail = "secrets store not configured on this daemon"
		return resp, nil
	}
	cred, cerr := s.secretsStore.BrokerCredential(ctx, conn.Username, conn.CredentialSecret)
	if cerr != nil {
		resp.Detail = fmt.Sprintf("resolve broker credential: %v", cerr)
		return resp, nil
	}

	info, err := describer.DescribeCredential(ctx, tracker.Conn{
		BaseURL: conn.BaseURL, Project: conn.Project, Credential: cred,
	})
	switch {
	case err == nil:
		resp.Reachable = true
		resp.CredentialValid = true
		resp.CredentialBreadth = breadthToProto(info.Breadth)
		resp.CredentialScopes = info.Scopes
		if !info.ExpiresAt.IsZero() {
			resp.CredentialExpiresAt = timestamppb.New(info.ExpiresAt)
		}
		// Keep the stored expiry in sync with what was just observed —
		// the same best-effort persistence SetTrackerConnection does.
		if serr := s.trackerStore.SetCredentialExpiry(ctx, conn.Username, conn.Name, info.ExpiresAt); serr != nil {
			log.Printf("[tracker] %s/%s: persist credential expiry: %v", conn.Username, conn.Name, serr)
		} else if resp.Connection != nil {
			resp.Connection.CredentialExpiresAt = resp.CredentialExpiresAt
		}
	case errors.Is(err, tracker.ErrCredentialInvalid):
		resp.Reachable = true
		resp.CredentialValid = false
		resp.Detail = err.Error()
	case errors.Is(err, tracker.ErrUnreachable):
		resp.Detail = err.Error()
	default:
		resp.Detail = err.Error()
	}
	return resp, nil
}

// describeCredentialBestEffort probes conn's own credential and, on
// success, persists its expiry onto conn (in-memory) and the store.
//
// Best-effort by design: SetTrackerConnection's whole point is
// registering a connection's METADATA (provider, project, which secret
// to use), and a describe failure here — the tracker briefly
// unreachable, a token not yet propagated upstream, a self-managed
// instance reachable only from a network the daemon doesn't have a
// route to yet — must never turn that write into an error. GetTrackerStatus
// is the verb an operator uses to find out WHY a describe isn't working;
// this one just doesn't let that block registering the connection.
func (s *ContainerServer) describeCredentialBestEffort(ctx context.Context, conn *tracker.Connection) {
	describer, err := s.trackerProviderFor(conn.Provider)
	if err != nil {
		log.Printf("[tracker] %s/%s: %v", conn.Username, conn.Name, err)
		return
	}
	cred, err := s.secretsStore.BrokerCredential(ctx, conn.Username, conn.CredentialSecret)
	if err != nil {
		log.Printf("[tracker] %s/%s: resolve broker credential: %v", conn.Username, conn.Name, err)
		return
	}
	info, err := describer.DescribeCredential(ctx, tracker.Conn{
		BaseURL: conn.BaseURL, Project: conn.Project, Credential: cred,
	})
	if err != nil {
		log.Printf("[tracker] %s/%s: describe credential: %v", conn.Username, conn.Name, err)
		return
	}
	if err := s.trackerStore.SetCredentialExpiry(ctx, conn.Username, conn.Name, info.ExpiresAt); err != nil {
		log.Printf("[tracker] %s/%s: persist credential expiry: %v", conn.Username, conn.Name, err)
		return
	}
	conn.CredentialExpiresAt = info.ExpiresAt
}

// breadthToProto converts the Go-level breadth classification to its
// proto enum.
func breadthToProto(b tracker.CredentialBreadth) pb.TrackerCredentialBreadth {
	switch b {
	case tracker.BreadthPreferred:
		return pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_PREFERRED
	case tracker.BreadthBroad:
		return pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_BROAD
	default:
		return pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_UNSPECIFIED
	}
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
// proto-facing one. credential_expires_at is populated best-effort by
// SetTrackerConnection / GetTrackerStatus (DescribeCredential); it stays
// unset on a connection that's never been successfully described.
func toProtoTrackerConnection(c *tracker.Connection) *pb.TrackerConnection {
	if c == nil {
		return nil
	}
	out := &pb.TrackerConnection{
		Username:         c.Username,
		Name:             c.Name,
		Provider:         c.Provider,
		BaseUrl:          c.BaseURL,
		Project:          c.Project,
		CredentialSecret: c.CredentialSecret,
	}
	if !c.CredentialExpiresAt.IsZero() {
		out.CredentialExpiresAt = timestamppb.New(c.CredentialExpiresAt)
	}
	return out
}
