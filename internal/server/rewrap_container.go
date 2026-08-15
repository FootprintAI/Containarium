package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Control-plane-driven key rotation (#1204), design phase 6 / resolved
// decision #5.
//
// The daemon exposes the primitive and holds no schedule: rotation cadence
// is tenant policy (90d, 1y, on-incident) owned by whoever owns the tenancy
// database. OSS ships no rotation scheduler.
//
// Rewrapping changes only the WRAPPING key. ZFS re-encrypts the dataset's
// master key, never the data, so a rotation costs the same on a 1 TB dataset
// as on a 1 GB one — which is what makes this a maintenance-window operation
// rather than a migration.

// RewrapContainer rotates the key protecting a container's data.
//
// Rotation is per-TENANT even though the RPC names a container: a tenant's
// containers share one encryptionroot by design (#1199), so rewrapping it
// re-keys all of them. The response lists every container affected, because
// a caller who believes they rotated one container's key will plan their
// next maintenance window wrongly.
func (s *ContainerServer) RewrapContainer(ctx context.Context, req *pb.RewrapContainerRequest) (*pb.RewrapContainerResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetNewKeyRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_key_ref is required")
	}
	// Rotating a tenant's key custody is an infrastructure operation, not a
	// tenant one — the same gate MoveContainer uses. A tenant holding their
	// own container must not be able to re-key it.
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := auth.AuthorizeTenant(ctx, req.GetUsername()); err != nil {
		return nil, err
	}

	var newRef zfskey.KeyRef
	if err := json.Unmarshal([]byte(req.GetNewKeyRef()), &newRef); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "new_key_ref is not a decodable KeyRef: %v", err)
	}

	containerName := fmt.Sprintf("%s-container", req.GetUsername())
	root, _, encrypted, err := s.encryption.encryptionRootFor(containerName)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve encryption state for %s: %v", containerName, err)
	}
	if !encrypted {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is not encrypted, so it has no key to rotate", containerName)
	}

	// Resolve the NEW key before touching anything. Rewrapping onto a key
	// this daemon cannot fetch again would make the data unreachable at the
	// next start, which is indistinguishable from having lost it.
	newKey, err := s.encryption.provider.Load(ctx, newRef)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"cannot resolve the new key for %s, so nothing was rotated: %v", containerName, err)
	}

	// ORDER IS THE WHOLE OF #1204 AC2. The rewrap happens first and the refs
	// are updated only once ZFS confirms it.
	//
	// Recording the new ref first would mean a failure between the two steps
	// leaves the dataset wrapped by the OLD key while every container records
	// the NEW one — and then neither key starts them. Recording afterwards
	// means a failure leaves old-wrapped and old-recorded: still exactly one
	// working key, which is the guarantee.
	if err := s.encryption.zfs.ChangeKey(ctx, root, newKey); err != nil {
		return nil, status.Errorf(codes.Internal,
			"rotating the key for %s failed and nothing was changed; the previous key is still the "+
				"one that works: %v", root, err)
	}

	// From here the dataset is on the new key. Any container still recording
	// the old ref would fail to start, so a failure below is reported loudly
	// rather than swallowed.
	rewrapped, err := s.encryption.recordRotation(root, newRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"the encryptionroot %s was rewrapped onto the new key, but recording it against every "+
				"container failed (%v). Those containers still name the retired key and will not "+
				"start until the ref is corrected", root, err)
	}

	log.Printf("[encryption] rotated the key for encryptionroot %s; %d container(s) now resolve the new ref",
		root, len(rewrapped))
	return &pb.RewrapContainerResponse{
		Message: fmt.Sprintf(
			"rotated the key for tenant encryptionroot %s; rotation is tenant-wide and covers %d container(s)",
			root, len(rewrapped)),
		RewrappedContainers: rewrapped,
	}, nil
}

// recordRotation points every container sharing an encryptionroot at the new
// key ref, and reports which ones.
//
// All of them, not just the one the caller named: they are opened by the
// same key, so a container left recording the retired ref would try it on
// its next start and fail.
func (h *encryptionHooks) recordRotation(root string, newRef zfskey.KeyRef) ([]string, error) {
	if !h.enabled() {
		return nil, fmt.Errorf("encryption is not configured on this daemon")
	}
	sharing, err := h.containersUnder(root)
	if err != nil {
		return nil, err
	}
	for _, name := range sharing {
		if err := h.refs.SetKeyRef(name, newRef); err != nil {
			return nil, fmt.Errorf("record the new key ref for %s: %w", name, err)
		}
	}
	return sharing, nil
}

// containersUnder lists the containers whose recorded pool resolves to the
// given encryptionroot.
func (h *encryptionHooks) containersUnder(root string) ([]string, error) {
	lister, ok := h.refs.(encryptionStateLister)
	if !ok {
		return nil, fmt.Errorf("this daemon cannot enumerate encrypted containers, so a rotation " +
			"cannot be recorded against all of them")
	}
	all, err := lister.ListEncrypted()
	if err != nil {
		return nil, fmt.Errorf("list encrypted containers: %w", err)
	}

	var sharing []string
	for _, name := range all {
		pool, err := h.refs.GetPool(name)
		if err != nil || pool == "" {
			continue
		}
		source, exists, err := h.pools.StoragePoolSource(pool)
		if err != nil || !exists {
			continue
		}
		if source == root {
			sharing = append(sharing, name)
		}
	}
	sort.Strings(sharing)
	return sharing, nil
}

// encryptionStateLister is the optional half of the state store that can
// enumerate encrypted containers.
//
// Optional because enumeration is only needed for rotation, and the
// incus-backed store gets it from a container list the daemon already has —
// while the migration and create paths need no such thing.
type encryptionStateLister interface {
	// ListEncrypted returns the names of containers carrying a key ref.
	ListEncrypted() ([]string, error)
}
