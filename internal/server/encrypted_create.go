package server

import (
	"fmt"
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
	if client == nil {
		return
	}
	s.setEncryptionHooks(tenantRoot,
		incusEncryptionState{
			setConfig: client.UpdateContainerConfig,
			getConfig: func(containerName, key string) (string, error) {
				cfg, _, err := client.GetRawInstance(containerName)
				if err != nil {
					return "", err
				}
				return cfg[key], nil
			},
		},
		incusStoragePools{
			createPool: client.CreateZFSPool,
			poolSource: client.StoragePoolSource,
		},
	)
}

// setEncryptionHooks is the substrate-free half, so the wiring — and the
// order it happens in relative to SetKeyProvider — is testable without Incus.
func (s *ContainerServer) setEncryptionHooks(tenantRoot string, refs encryptionStateStore, pools storagePoolAPI) {
	if tenantRoot == "" {
		return
	}
	s.encryption = &encryptionHooks{
		// Whatever custody is configured right now. Nil is the normal case
		// at this point in startup and keeps the hooks inert; SetKeyProvider
		// attaches one later if --zfs-keys-dir was given.
		provider:   s.keyProvider,
		zfs:        zfscrypt.NewManager(nil),
		cache:      zfskey.NewCache(zfsKeyCacheTTL),
		refs:       refs,
		pools:      pools,
		tenantRoot: tenantRoot,
	}
}

// SetKeyProvider installs key custody, and attaches it to the encryption
// hooks if they are already wired.
//
// The re-attach is what makes startup order irrelevant. Without it, hooks
// built before custody was configured would keep a nil provider and stay
// inert forever — every encrypted create failing on a daemon the operator
// had configured correctly, with an error pointing at the create path
// rather than at startup.
//
// This is the switch #1342 exists for: until a provider is installed,
// validateEncryption refuses every encrypted create, which is the state
// every OSS daemon ships in.
func (s *ContainerServer) SetKeyProvider(provider zfskey.KeyProvider) {
	s.keyProvider = provider
	if s.encryption != nil {
		s.encryption.provider = provider
	}
}

// keyProviderFromDir builds the file-based key custody --zfs-keys-dir asks
// for, or nothing at all when the flag is unset.
//
// Unset is not an error: it is the default, and it must leave the daemon
// exactly as it was — refusing encrypted creates rather than failing to
// start, and certainly rather than quietly enabling encryption for every
// deployment that never asked for it.
func keyProviderFromDir(dir string) (zfskey.KeyProvider, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	provider, err := zfskey.NewFileKeyProvider(dir)
	if err != nil {
		return nil, fmt.Errorf("configure key custody at %s: %w", dir, err)
	}
	return provider, nil
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
