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
// Best-effort on a per-key basis: if one stamp fails (e.g.
// container doesn't exist), the rest still proceed. Returns the
// count of successfully-stamped secrets.
//
// Phase 4.3 — dispatches per-secret based on the delivery
// mode. "env" rows stamp via incus config (as before); "file"
// rows write to /run/secrets/<NAME> inside the container with
// mode 0400. /run is tmpfs on every distro the daemon
// supports, so file-mode secrets get the in-memory ephemeral
// disposal property for free: when the container stops, the
// tmpfs evaporates and the plaintext is gone.
//
// File-mode secrets must be re-stamped on every container
// start (since the tmpfs file doesn't survive a stop/start),
// which the daemon already does at CreateContainer +
// StartContainer + RefreshSecrets call sites.
func (s *ContainerServer) stampSecretsOnLXC(ctx context.Context, username string) (int, error) {
	if s.secretsStore == nil {
		return 0, errors.New("secrets store not configured")
	}
	secretMap, err := s.secretsStore.LoadAllForUserWithDelivery(ctx, username)
	if err != nil {
		return 0, fmt.Errorf("load secrets: %w", err)
	}

	containerName := username + "-container"
	stamped := 0

	// File mode needs the /run/secrets directory present and
	// mode-tight before we write into it. Do this once per
	// stamp pass if any file-mode rows exist. Failure is
	// fatal for THIS pass (any file-mode write below would
	// fail anyway), so we surface and count those rows as
	// not stamped.
	hasFileMode := false
	for _, v := range secretMap {
		if v.Delivery == secrets.DeliveryFile {
			hasFileMode = true
			break
		}
	}
	if hasFileMode {
		// mkdir + chmod is idempotent. Phase B-2 (audit
		// C-MED-4 polish) — the dir is mode 0750
		// root:<username> so the tenant's process group
		// can traverse it but no other user can. /run is
		// tmpfs on systemd distros so this dir vanishes on
		// container stop — that's the design.
		//
		// Username lookup: the container's tenant user is
		// `<username>` by convention (created at
		// CreateContainer time). chown's by-name form
		// resolves it via the container's /etc/passwd; if
		// the user doesn't exist (e.g. early-boot race or
		// a container provisioned outside the daemon) the
		// chown errors and we fall back to root-only mode
		// 0700 + file 0400, same as Phase B-1.
		prepCmd := fmt.Sprintf(
			"mkdir -p /run/secrets && chown root:%s /run/secrets && chmod 0750 /run/secrets",
			username,
		)
		if err := s.manager.Exec(containerName, []string{"sh", "-c", prepCmd}); err != nil {
			log.Printf("[secrets] tenant chown on /run/secrets failed for %s (%v) — falling back to root-only mode", containerName, err)
			// Fallback: root-only dir. Files will be
			// 0400 root, app must run as root or use
			// sudo. Better than failing the whole stamp.
			if err := s.manager.Exec(containerName, []string{"sh", "-c",
				"mkdir -p /run/secrets && chmod 0700 /run/secrets",
			}); err != nil {
				log.Printf("[secrets] failed to prepare /run/secrets on %s: %v (file-mode rows will be skipped)", containerName, err)
				hasFileMode = false
			}
		}
	}

	for k, sv := range secretMap {
		switch sv.Delivery {
		case secrets.DeliveryFile:
			if !hasFileMode {
				continue
			}
			path := "/run/secrets/" + k
			// Write the file mode 0400 (root-only). The
			// post-write chown/chmod below relaxes the
			// group bit so the tenant user can read.
			// We do that as a separate exec rather than
			// passing uid/gid to WriteFile because the
			// container's /etc/passwd is the source of
			// truth for the UID; resolving it server-side
			// would be fragile.
			if err := s.manager.WriteFile(containerName, path, []byte(sv.Value), "0400"); err != nil {
				log.Printf("[secrets] failed to write file-mode %s on %s: %v (continuing)", k, containerName, err)
				continue
			}
			// Try the chown+chmod fix-up. Best-effort —
			// if the tenant user doesn't exist, the
			// stamp still succeeds at the file level
			// (visible to root) and the operator can
			// debug from the warning.
			fixupCmd := fmt.Sprintf(
				"chown root:%s %q && chmod 0440 %q",
				username, path, path,
			)
			if err := s.manager.Exec(containerName, []string{"sh", "-c", fixupCmd}); err != nil {
				log.Printf("[secrets] chown/chmod %s on %s failed (%v) — file stays root-only 0400", k, containerName, err)
			}
		default: // env (and any unknown future mode falls back to env semantics)
			if err := s.manager.SetEnv(containerName, k, sv.Value); err != nil {
				log.Printf("[secrets] failed to stamp %s on %s: %v (continuing)", k, containerName, err)
				continue
			}
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
