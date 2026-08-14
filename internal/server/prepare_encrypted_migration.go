package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Migration pre-flight for encrypted containers (#1360, from #1203), design
// §3 hook row 5 and §5's cross-VM failure mode.
//
// Two questions only the destination can answer, asked together because they
// are needed at the same moment — before a byte is copied:
//
//   - Can this daemon's key custody resolve the source's KeyRef? Without
//     asking, a migration copies an entire container and only then discovers
//     the destination cannot unlock it, leaving an unstartable shell.
//   - Which storage pool is sourced at that tenant's encryptionroot? The copy
//     has to land inside it, and the destination is the only party that can
//     create it (#1341).
//
// Only the KeyRef crosses the wire. Key material never does — that is the
// design's flat rule, and the reason this is a resolve-check rather than a
// key exchange.

// PrepareEncryptedMigration is the destination side of the pre-flight.
//
// A destination that cannot take the container answers plainly —
// can_resolve=false with a reason — rather than returning an error. The
// source has to put something in front of an operator, and "the destination
// has no key custody configured" is a different problem from "the peer is
// unreachable". Errors are reserved for malformed requests and authorization.
func (s *ContainerServer) PrepareEncryptedMigration(ctx context.Context, req *pb.PrepareEncryptedMigrationRequest) (*pb.PrepareEncryptedMigrationResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetTenant() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant is required")
	}
	if req.GetKeyRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_ref is required")
	}
	// Peer-to-peer only, exactly like AdoptMigratedContainer: this call makes
	// a daemon provision tenant storage and probe its own key custody. A user
	// token must not be able to drive either, even for its own username.
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := auth.AuthorizeTenant(ctx, req.GetUsername()); err != nil {
		return nil, err
	}

	var ref zfskey.KeyRef
	if err := json.Unmarshal([]byte(req.GetKeyRef()), &ref); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "key_ref is not a decodable KeyRef: %v", err)
	}

	if !s.encryption.enabled() {
		return refused("this daemon has no key custody configured, so it cannot unlock %s's data "+
			"after a migration (see --zfs-keys-dir)", req.GetUsername()), nil
	}

	// Resolve BEFORE provisioning. A tenant this daemon cannot serve should
	// leave no storage behind — otherwise a refused pre-flight still litters
	// the destination with pools for tenants that never arrive.
	if _, err := s.encryption.provider.Load(ctx, ref); err != nil {
		return refused("this daemon's key custody cannot resolve the key ref for tenant %s: %v",
			req.GetTenant(), err), nil
	}

	pool, _, err := s.encryption.EnsureTenantStorage(ctx, req.GetTenant())
	if err != nil {
		return refused("this daemon resolved the key for tenant %s but could not provision their "+
			"encrypted storage: %v", req.GetTenant(), err), nil
	}
	if pool == "" {
		// enabled() said yes and EnsureTenantStorage returned no pool: the
		// hooks are half-wired. Refusing keeps the source from copying into
		// the default pool, which would arrive unencrypted.
		return refused("this daemon resolved the key for tenant %s but resolved no storage pool "+
			"for them", req.GetTenant()), nil
	}

	log.Printf("[move] pre-flight accepted for %s (tenant %s): key resolved, storage pool %s ready",
		req.GetUsername(), req.GetTenant(), pool)
	return &pb.PrepareEncryptedMigrationResponse{CanResolve: true, StoragePool: pool}, nil
}

// refused builds a plain "no, and here is why" answer.
func refused(format string, args ...any) *pb.PrepareEncryptedMigrationResponse {
	reason := fmt.Sprintf(format, args...)
	log.Printf("[move] pre-flight refused: %s", reason)
	return &pb.PrepareEncryptedMigrationResponse{CanResolve: false, Reason: reason}
}

// migrationRef reports the durable KeyRef and storage pool recorded for a
// container, and false when the container is not encrypted.
//
// Read-only, and deliberately tolerant of a daemon with no encryption wired:
// on that daemon every container is unencrypted, which is the correct answer
// rather than an error.
func (h *encryptionHooks) migrationRef(containerName string) (ref zfskey.KeyRef, pool string, ok bool, err error) {
	if !h.enabled() {
		return zfskey.KeyRef{}, "", false, nil
	}
	ref, present, err := h.refs.GetKeyRef(containerName)
	if err != nil {
		return zfskey.KeyRef{}, "", false, fmt.Errorf("read the encryption key ref of %s: %w", containerName, err)
	}
	if !present {
		return zfskey.KeyRef{}, "", false, nil
	}
	pool, err = h.refs.GetPool(containerName)
	if err != nil {
		return zfskey.KeyRef{}, "", false, fmt.Errorf("read the storage pool of %s: %w", containerName, err)
	}
	return ref, pool, true, nil
}
