package server

import (
	"log"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Wiring for the encrypted create path (#1341), per
// docs/architecture/per-tenant-encrypted-storage-pools.md.

// zfsKeyCacheTTL bounds how long a tenant's key stays resident after its last
// use. Long enough that a stop/start cycle does not re-hit key custody, short
// enough that an idle tenant's key does not sit in daemon memory forever.
const zfsKeyCacheTTL = 30 * time.Minute

// encryptionTenantFor decides whose key a container is encrypted with.
//
// On this build the username IS the tenant: validateTenantID rejects any
// tenant_id other than unset or "default", so there is no other tenancy to
// scope a key by — and scoping by "default" would put every user of the
// daemon under one encryptionroot. No isolation at all, and silently.
//
// A real tenant_id wins where one exists (the cloud build's org-scoped
// tenancy), because an org's several users must share one encryptionroot or
// they cannot share datasets.
func encryptionTenantFor(req *pb.CreateContainerRequest) string {
	if id := req.GetTenantId(); id != "" && id != defaultTenantID {
		return id
	}
	return req.GetUsername()
}

// recordEncryptedPlacement stores the key ref and storage pool on a
// just-created container, and removes the container if it cannot.
//
// Deleting is the right failure mode, not tidiness. The container's data is
// already encrypted under the tenant's key; without a recorded placement
// nothing can name its encryptionroot, so it can never be started and never
// safely reused — and its name would block the next create. Leaving one
// behind is worse than failing the create.
//
// A no-op for an unencrypted create, which is every container today.
func (s *ContainerServer) recordEncryptedPlacement(req *pb.CreateContainerRequest, containerName string, ref zfskey.KeyRef, pool string) error {
	if !req.GetEncrypted() {
		return nil
	}

	err := s.encryption.RecordPlacement(containerName, ref, pool)
	if err == nil {
		return nil
	}

	log.Printf("[encryption] could not record placement for %s (pool %s): %v — removing the container, "+
		"because nothing could name its encryptionroot afterwards", containerName, pool, err)

	if delErr := s.manager.Delete(req.GetUsername(), true); delErr != nil {
		return status.Errorf(codes.Internal,
			"created %s but could not record its encryption placement (%v), and removing it also "+
				"failed (%v) — the container is encrypted under tenant %q with nothing recording "+
				"which key unlocks it, and must be deleted by hand before the name can be reused",
			containerName, err, delErr, encryptionTenantFor(req))
	}
	return status.Errorf(codes.Internal,
		"created %s but could not record its encryption placement (%v); the container was removed "+
			"rather than left unopenable", containerName, err)
}

// SetEncryptionStorage wires the per-tenant encryption hooks onto the server.
//
// Called once at daemon startup with the tenant dataset root and the Incus
// client the daemon already holds. The hooks stay inert until a KeyProvider
// is also configured (#1342) — encryptionHooks.enabled() is false without one
// — so wiring this early changes nothing an operator can observe.
//
// That ordering is deliberate and load-bearing: a KeyProvider configured
// before the create path could genuinely encrypt would make
// validateEncryption start PASSING while the daemon handed back plaintext.
func (s *ContainerServer) SetEncryptionStorage(tenantRoot string, client *incus.Client) {
	if tenantRoot == "" || client == nil {
		return
	}
	s.encryption = &encryptionHooks{
		provider: s.keyProvider, // nil until #1342, which keeps the hooks inert
		zfs:      zfscrypt.NewManager(nil),
		cache:    zfskey.NewCache(zfsKeyCacheTTL),
		refs: incusEncryptionState{
			setConfig: client.UpdateContainerConfig,
			getConfig: func(containerName, key string) (string, error) {
				cfg, _, err := client.GetRawInstance(containerName)
				if err != nil {
					return "", err
				}
				return cfg[key], nil
			},
		},
		pools: incusStoragePools{
			createPool: client.CreateZFSPool,
			poolSource: client.StoragePoolSource,
		},
		tenantRoot: tenantRoot,
	}
}

// DefaultTenantRoot derives the tenant dataset root from the daemon's own
// storage pool, for when --zfs-tenant-root is not set.
//
// Tenant encryptionroots are siblings of the default pool's source, not
// children of it: a child would sit inside the dataset Incus manages, where
// Incus's housekeeping does not expect datasets it did not create.
//
// Returns "" when the pool cannot be read or is not ZFS-backed, which leaves
// encryption unwired rather than guessing at a path — an encrypted create
// then fails loudly instead of provisioning somewhere arbitrary.
func DefaultTenantRoot(client *incus.Client) string {
	if client == nil {
		return ""
	}
	source, exists, err := client.StoragePoolSource(client.StoragePool())
	if err != nil || !exists || source == "" {
		return ""
	}
	return zpoolOf(source) + "/tenants"
}

// zpoolOf returns the ZFS pool a dataset path belongs to.
func zpoolOf(dataset string) string {
	if i := strings.Index(dataset, "/"); i >= 0 {
		return dataset[:i]
	}
	return dataset
}
