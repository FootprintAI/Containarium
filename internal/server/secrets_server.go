package server

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetSecretsStore wires the tenant-secrets backend onto the server.
// Called from dual_server.go after the Postgres connection + master
// key have been resolved. Nil store keeps the SecretsService RPCs
// returning Unavailable (--standalone daemons).
func (s *ContainerServer) SetSecretsStore(store *secrets.Store) {
	s.secretsStore = store
}

// SetSecret creates or updates a tenant secret. Idempotent —
// repeated calls with the same (username, name) bump the version
// and replace the value. Admin JWT required (design decision #3).
func (s *ContainerServer) SetSecret(ctx context.Context, req *pb.SetSecretRequest) (*pb.SetSecretResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsWrite); err != nil {
		return nil, err
	}
	if s.secretsStore == nil {
		return nil, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	meta, err := s.secretsStore.Set(ctx, req.Username, req.Name, req.Value, req.Delivery)
	if err != nil {
		return nil, mapSecretError(err)
	}

	// Audit. Never log the value.
	log.Printf("[secrets] set %s/%s version=%d delivery=%s", req.Username, req.Name, meta.Version, meta.Delivery)

	msg := "secret created"
	if meta.Version > 1 {
		msg = fmt.Sprintf("secret updated to version %d", meta.Version)
	}
	return &pb.SetSecretResponse{
		Message: msg,
		Secret:  toProtoSecretMetadata(meta),
	}, nil
}

// GetSecret returns the decrypted plaintext value. Always
// audit-logged. The agent / operator sees what they wrote (decision
// #6); v2 layers a per-secret read_via_api flag for write-only
// rotation.
func (s *ContainerServer) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsRead); err != nil {
		return nil, err
	}
	if s.secretsStore == nil {
		return nil, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	meta, value, err := s.secretsStore.Get(ctx, req.Username, req.Name)
	if err != nil {
		return nil, mapSecretError(err)
	}

	log.Printf("[secrets] get %s/%s version=%d", req.Username, req.Name, meta.Version)
	return &pb.GetSecretResponse{
		Secret: toProtoSecretMetadata(meta),
		Value:  value,
	}, nil
}

// ListSecrets returns metadata for every secret owned by the
// tenant. Values are never returned by this path.
func (s *ContainerServer) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsRead); err != nil {
		return nil, err
	}
	if s.secretsStore == nil {
		return nil, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	list, err := s.secretsStore.List(ctx, req.Username)
	if err != nil {
		return nil, mapSecretError(err)
	}

	out := make([]*pb.SecretMetadata, 0, len(list))
	for i := range list {
		out = append(out, toProtoSecretMetadata(&list[i]))
	}
	return &pb.ListSecretsResponse{Secrets: out}, nil
}

// DeleteSecret removes a single secret. Does NOT cascade-clean
// env-var stamps on running containers — callers invoke
// RefreshSecrets if they want the change to reach a running
// process.
func (s *ContainerServer) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsWrite); err != nil {
		return nil, err
	}
	if s.secretsStore == nil {
		return nil, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	if err := s.secretsStore.Delete(ctx, req.Username, req.Name); err != nil {
		return nil, mapSecretError(err)
	}

	log.Printf("[secrets] delete %s/%s", req.Username, req.Name)
	return &pb.DeleteSecretResponse{
		Message: fmt.Sprintf("secret %s deleted", req.Name),
	}, nil
}

// RefreshSecrets re-stamps the LXC's environment.<NAME> config
// keys from the current secret-store state for the tenant. Running
// processes keep their old env (POSIX semantics); new execs see
// the refreshed values.
func (s *ContainerServer) RefreshSecrets(ctx context.Context, req *pb.RefreshSecretsRequest) (*pb.RefreshSecretsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsWrite); err != nil {
		return nil, err
	}
	if s.secretsStore == nil {
		return nil, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	stamped, err := s.stampSecretsOnLXC(ctx, req.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "refresh secrets: %v", err)
	}

	log.Printf("[secrets] refresh %s: stamped=%d", req.Username, stamped)
	return &pb.RefreshSecretsResponse{
		Message: fmt.Sprintf("re-stamped %d secret(s) on %s-container; new execs will see updated values", stamped, req.Username),
		Stamped: int32(stamped),
	}, nil
}

// stampSecretsOnLXC reads every secret owned by `username`,
// decrypts, and `incus config set environment.<NAME>=<value>`s
// each one onto `<username>-container`. Used by RefreshSecrets
// directly and called from CreateContainer / StartContainer once
// phase 4 wires them up.
//
// Best-effort on a per-key basis: if one SetEnv call fails (e.g.
// container doesn't exist), the rest still proceed. Returns the
// count of successfully-stamped vars.
func (s *ContainerServer) stampSecretsOnLXC(ctx context.Context, username string) (int, error) {
	if s.secretsStore == nil {
		return 0, errors.New("secrets store not configured")
	}
	envMap, err := s.secretsStore.LoadAllForUser(ctx, username)
	if err != nil {
		return 0, fmt.Errorf("load secrets: %w", err)
	}

	containerName := username + "-container"
	stamped := 0
	for k, v := range envMap {
		if err := s.manager.SetEnv(containerName, k, v); err != nil {
			log.Printf("[secrets] failed to stamp %s on %s: %v (continuing)", k, containerName, err)
			continue
		}
		stamped++
	}
	return stamped, nil
}

// mapSecretError maps store errors to gRPC status codes. Centralized
// so the five RPC methods stay short.
func mapSecretError(err error) error {
	if errors.Is(err, secrets.ErrNotFound) {
		return status.Error(codes.NotFound, "secret not found")
	}
	// pkg/core/secrets validation errors carry the right message for
	// the caller — surface as InvalidArgument.
	msg := err.Error()
	if isValidationError(msg) {
		return status.Error(codes.InvalidArgument, msg)
	}
	return status.Errorf(codes.Internal, "%v", err)
}

// isValidationError returns true for the small set of validation
// errors from pkg/core/secrets. Cheap substring match — these
// errors are stable strings.
func isValidationError(msg string) bool {
	keywords := []string{
		"name must match",
		"value exceeds",
		"username is required",
	}
	for _, kw := range keywords {
		if containsCI(msg, kw) {
			return true
		}
	}
	return false
}

// containsCI is a tiny case-insensitive substring check that avoids
// pulling in strings.ToLower / Contains for one match each — keeps
// this file's dep footprint local.
func containsCI(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if lowerEqual(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func lowerEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// toProtoSecretMetadata converts the storage-layer struct to the
// proto-facing one. Times become RFC3339 strings (proto avoids
// timestamppb for consistency with the rest of the secrets surface).
func toProtoSecretMetadata(m *secrets.SecretMetadata) *pb.SecretMetadata {
	if m == nil {
		return nil
	}
	return &pb.SecretMetadata{
		Username:  m.Username,
		Name:      m.Name,
		Version:   m.Version,
		CreatedAt: m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt: m.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Delivery:  m.Delivery,
	}
}
