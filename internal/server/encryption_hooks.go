package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// Container lifecycle hooks for per-tenant ZFS encryption (#1199, #1201),
// phases 3 and 4 of docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md.
//
// The hooks are deliberately no-ops for unencrypted containers, which is
// every container today: a container carries a KeyRef only if it was
// created encrypted, and without one these do nothing at all. That keeps
// the default path byte-for-byte unchanged while the encrypted path is
// still being built out.
//
// The ZFS behaviour these hooks depend on is verified against a real pool
// (#1200) — see the pkg/core/zfscrypt package doc. The tests here prove
// only the orchestration: what runs, in what order, and what happens on
// failure.

// keyRefConfigKey is the Incus config key the durable KeyRef is stored
// under, so a restarted daemon — or a migration destination — can
// re-resolve the same key without holding any state itself.
const keyRefConfigKey = "user.containarium.zfs_key_ref"

// poolConfigKey is the Incus config key recording which storage pool a
// container was placed on.
//
// The pool's source dataset IS the container's encryptionroot, so this is
// how a restarted daemon finds the dataset to unlock. It is read back rather
// than recomputed from the tenant naming convention on purpose: recomputing
// means the day the convention changes, every existing container resolves to
// a dataset that is not theirs.
const poolConfigKey = "user.containarium.zfs_pool"

// encryptionStateStore reads and writes a container's durable encryption
// state: which key unlocks it, and which storage pool it lives on. An
// interface so the hooks are testable without Incus.
type encryptionStateStore interface {
	// GetKeyRef returns the stored ref and whether one was present.
	GetKeyRef(containerName string) (zfskey.KeyRef, bool, error)
	// SetKeyRef persists the ref on the container.
	SetKeyRef(containerName string, ref zfskey.KeyRef) error
	// GetPool returns the storage pool the container was placed on, or ""
	// when none was recorded.
	GetPool(containerName string) (string, error)
	// SetPool persists the storage pool on the container.
	SetPool(containerName, pool string) error
}

// storagePoolAPI is the slice of the Incus storage-pool surface the hooks
// need. Narrow on purpose: the hooks provision one pool per tenant and read
// back where it points, and nothing else.
type storagePoolAPI interface {
	// CreateZFSPool creates a zfs-driver pool sourced at an existing dataset.
	CreateZFSPool(name, source string) error
	// StoragePoolSource reports where a pool points, and whether it exists.
	StoragePoolSource(name string) (source string, exists bool, err error)
}

// encryptionHooks carries the collaborators the lifecycle hooks need.
// A nil *encryptionHooks is a valid no-op receiver, so call sites do not
// need to branch on whether encryption is configured.
type encryptionHooks struct {
	provider zfskey.KeyProvider
	zfs      *zfscrypt.Manager
	cache    *zfskey.Cache
	refs     encryptionStateStore
	pools    storagePoolAPI
	// tenantRoot is the dataset every tenant encryptionroot is created
	// under, e.g. "incus-local/tenants".
	tenantRoot string
}

// enabled reports whether encryption is wired at all.
func (h *encryptionHooks) enabled() bool {
	return h != nil && h.provider != nil && h.zfs != nil && h.refs != nil &&
		h.pools != nil && h.tenantRoot != ""
}

// encryptionRootFor resolves the dataset that is a container's
// encryptionroot, and false when the container is not encrypted.
//
// The encryptionroot is the SOURCE of the storage pool the container lives
// on, not the container's own dataset. Incus clones the image to build an
// instance, and a clone inherits its key from the dataset it is made inside
// (#1335) — so the container's own dataset has no key to load, and the one
// that does is the pool's source.
func (h *encryptionHooks) encryptionRootFor(containerName string) (root string, ref zfskey.KeyRef, ok bool, err error) {
	if !h.enabled() {
		return "", zfskey.KeyRef{}, false, nil
	}
	ref, present, err := h.refs.GetKeyRef(containerName)
	if err != nil || !present {
		return "", zfskey.KeyRef{}, false, err
	}

	pool, err := h.refs.GetPool(containerName)
	if err != nil {
		return "", zfskey.KeyRef{}, false, fmt.Errorf("read the storage pool of %s: %w", containerName, err)
	}
	// A ref with no pool is a half-written record. Refuse rather than treat
	// the container as unencrypted: it IS encrypted, and starting it as
	// though it were not would run it on storage nothing can account for.
	if pool == "" {
		return "", zfskey.KeyRef{}, false, fmt.Errorf(
			"container %s records an encryption key ref but no storage pool, so its encryptionroot "+
				"cannot be resolved; it was created by a daemon that did not record placement, or the "+
				"record was written partially", containerName)
	}

	source, exists, err := h.pools.StoragePoolSource(pool)
	if err != nil {
		return "", zfskey.KeyRef{}, false, fmt.Errorf("read storage pool %s for %s: %w", pool, containerName, err)
	}
	if !exists {
		return "", zfskey.KeyRef{}, false, fmt.Errorf(
			"container %s is recorded on storage pool %s, which does not exist", containerName, pool)
	}
	if source == "" {
		return "", zfskey.KeyRef{}, false, fmt.Errorf(
			"storage pool %s (for %s) has no source dataset, so there is no encryptionroot to unlock",
			pool, containerName)
	}
	return source, ref, true, nil
}

// tenantPoolName is the Incus storage pool a tenant's containers live on.
// Stable across daemon restarts — it is how the daemon finds the pool it
// created — and tenant-scoped so `incus storage list` stays readable.
func tenantPoolName(tenant string) string { return "containarium-tenant-" + tenant }

// tenantDataset is the ZFS dataset that is a tenant's encryptionroot.
//
// The tenant name is interpolated into a dataset path AND an Incus pool
// name, so it is validated rather than trusted: a name carrying a slash or
// a ".." would name somebody else's dataset, and the caller would never
// know because everything downstream would succeed.
func tenantDataset(root, tenant string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("no tenant dataset root is configured, so a tenant encryptionroot cannot be placed")
	}
	if err := validateTenantName(tenant); err != nil {
		return "", err
	}
	return strings.TrimSuffix(root, "/") + "/" + tenant, nil
}

// validateTenantName rejects anything that could name something other than a
// single child dataset of the tenant root.
func validateTenantName(tenant string) error {
	switch {
	case tenant == "":
		return fmt.Errorf("encryption: a tenant is required")
	case strings.ContainsAny(tenant, "/ \t\n\r"):
		return fmt.Errorf("invalid tenant %q: it becomes a dataset path component and must not contain a separator or whitespace", tenant)
	case strings.HasPrefix(tenant, "-"):
		return fmt.Errorf("invalid tenant %q: a leading dash would be read as a flag by zfs", tenant)
	case tenant == "." || tenant == "..":
		return fmt.Errorf("invalid tenant %q: it would name the tenant root itself or its parent", tenant)
	}
	return nil
}

// EnsureTenantStorage makes a tenant's encrypted storage exist and reports
// the Incus pool a container for that tenant must be created on.
//
// Replaces PreCreate. The old hook made a per-CONTAINER encrypted dataset
// and pointed Incus at it; Incus will not build an instance on a dataset
// that already exists, because it creates the instance volume by cloning the
// image snapshot — and a clone inherits encryption from its origin, not from
// where it is placed (#1335). The encryptionroot therefore has to sit above
// the level Incus manages: a storage pool sourced at the tenant's encrypted
// dataset, so images and instances alike are cloned inside it.
//
// Order is the whole of #1199 AC3. The key is resolved BEFORE anything is
// created, so a KeyProvider outage fails having touched nothing.
//
// # Rollback is asymmetric, and that is deliberate
//
// PreCreate destroyed its dataset whenever a later step failed. That was
// right when the dataset belonged to one container. It is now the TENANT's
// encryptionroot, shared by every container they own, so destroying it
// because an unrelated container's create failed would destroy live data.
// Only a dataset THIS call created is rolled back; one that was already
// there is left exactly as found.
func (h *encryptionHooks) EnsureTenantStorage(ctx context.Context, tenant string) (pool string, ref zfskey.KeyRef, err error) {
	if !h.enabled() {
		return "", zfskey.KeyRef{}, nil
	}

	dataset, err := tenantDataset(h.tenantRoot, tenant)
	if err != nil {
		return "", zfskey.KeyRef{}, err
	}
	pool = tenantPoolName(tenant)

	// Wrap is per-tenant and idempotent: a tenant's containers share one
	// encryptionroot, so the second container reuses the first's key rather
	// than minting a second one that ZFS would treat as a separate root.
	key, ref, err := h.provider.Wrap(ctx, tenant)
	if err != nil {
		// Nothing has been created, so there is nothing to undo. The create
		// fails as Unavailable and the operator retries when key custody is
		// back.
		return "", zfskey.KeyRef{}, fmt.Errorf("cannot obtain an encryption key for tenant %s: %w", tenant, err)
	}
	h.cachePut(tenant, key)

	createdDataset, err := h.ensureTenantDataset(ctx, dataset, key)
	if err != nil {
		return "", zfskey.KeyRef{}, err
	}

	if err := h.ensureTenantPool(ctx, pool, dataset, createdDataset); err != nil {
		return "", zfskey.KeyRef{}, err
	}
	return pool, ref, nil
}

// ensureTenantDataset makes the tenant's encryptionroot exist, and reports
// whether this call created it — which is what decides whether a later
// failure may destroy it.
//
// An existing dataset is verified to be its own encryptionroot rather than
// assumed. A plaintext dataset sitting at the tenant's path is the quietest
// possible failure: the pool would be built on it, every container inside
// would be unencrypted, and every daemon-side signal would say otherwise.
func (h *encryptionHooks) ensureTenantDataset(ctx context.Context, dataset string, key zfskey.Key) (created bool, err error) {
	exists, err := h.zfs.Exists(ctx, dataset)
	if err != nil {
		return false, fmt.Errorf("check the tenant encryptionroot %s: %w", dataset, err)
	}
	if !exists {
		// The root the tenant datasets sit under is derived from the storage
		// pool and may never have existed on this host. `zfs create` does not
		// make intermediates, so without this every encrypted create on a
		// fresh host fails with "parent does not exist" (#1341).
		if err := h.zfs.EnsureParent(ctx, dataset); err != nil {
			return false, fmt.Errorf("cannot prepare the tenant dataset root for %s: %w", dataset, err)
		}
		if err := h.zfs.CreateEncrypted(ctx, dataset, key); err != nil {
			return false, fmt.Errorf("cannot create the tenant encryptionroot %s: %w", dataset, err)
		}
		return true, nil
	}

	root, err := h.zfs.EncryptionRoot(ctx, dataset)
	if err != nil {
		return false, fmt.Errorf(
			"dataset %s already exists but its encryption state could not be read (%w) — refusing "+
				"to place a tenant pool on a dataset that may not be encrypted", dataset, err)
	}
	if root != dataset {
		return false, fmt.Errorf(
			"dataset %s already exists and its encryptionroot is %q, not itself — a tenant pool "+
				"placed here would not give its containers that tenant's own key", dataset, root)
	}
	return false, nil
}

// ensureTenantPool makes the Incus pool sourced at the tenant's
// encryptionroot exist, rolling back a dataset this call created if it
// cannot.
//
// A pool that already exists on a DIFFERENT source is refused, never
// repointed: repointing would move the containers already on it onto another
// encryptionroot underneath them.
func (h *encryptionHooks) ensureTenantPool(ctx context.Context, pool, dataset string, createdDataset bool) error {
	rollback := func(cause error) error {
		if !createdDataset {
			// Not ours to destroy — it is another container's encryptionroot.
			return cause
		}
		if derr := h.zfs.Destroy(ctx, dataset); derr != nil {
			return fmt.Errorf(
				"%w, and rolling back the tenant encryptionroot %s also failed (%v) — that dataset "+
					"is unreferenced and must be destroyed manually before the tenant can be "+
					"provisioned again", cause, dataset, derr)
		}
		return cause
	}

	source, exists, err := h.pools.StoragePoolSource(pool)
	if err != nil {
		return rollback(fmt.Errorf("cannot read storage pool %s: %w", pool, err))
	}
	if exists {
		if source != dataset {
			return rollback(fmt.Errorf(
				"storage pool %s already exists and is sourced at %q, not the tenant encryptionroot "+
					"%s; refusing to reuse or repoint it, because its existing containers would be "+
					"moved onto a different encryptionroot underneath them", pool, source, dataset))
		}
		return nil
	}

	if err := h.pools.CreateZFSPool(pool, dataset); err != nil {
		return rollback(fmt.Errorf("cannot create storage pool %s on %s: %w", pool, dataset, err))
	}
	return nil
}

// PreStart loads the container's encryption key so its dataset can be
// mounted.
//
// A failure here must prevent the start. The container's data is
// unreadable without the key, so letting it boot would produce a
// container whose storage silently is not there — far worse than a
// refused start, which is at least legible (design §5: KeyProvider down
// at start time → FailedPrecondition, the LXC stays stopped).
func (h *encryptionHooks) PreStart(ctx context.Context, containerName string) error {
	dataset, ref, ok, err := h.encryptionRootFor(containerName)
	if err != nil {
		return fmt.Errorf("resolve encryption state for %s: %w", containerName, err)
	}
	if !ok {
		return nil // not an encrypted container
	}

	tenant := tenantFromRef(ref, containerName)
	key, cached := h.cacheGet(tenant)
	if !cached {
		key, err = h.provider.Load(ctx, ref)
		if err != nil {
			// The container stays stopped, by design: it is
			// unreadable until key custody recovers.
			return fmt.Errorf("cannot load the encryption key for %s: %w", containerName, err)
		}
		h.cachePut(tenant, key)
	}

	if err := h.zfs.LoadKey(ctx, dataset, key); err != nil {
		return fmt.Errorf("cannot unlock the dataset for %s: %w", containerName, err)
	}
	return nil
}

// PostStop drops the key so a stopped container's dataset is ciphertext,
// including to host root (#1201).
//
// Best-effort by design: the container has already stopped, so failing
// the RPC would report a stop that did happen as a failure. The operator
// still needs to know, so every non-trivial outcome is logged.
//
// "Key still in use" is the expected case when the tenant has another
// container running under the same encryptionroot — a tenant's
// containers share one — and is not an error.
func (h *encryptionHooks) PostStop(ctx context.Context, containerName string) {
	dataset, ref, ok, err := h.encryptionRootFor(containerName)
	if err != nil {
		log.Printf("[encryption] could not resolve encryption state for %s while stopping: %v", containerName, err)
		return
	}
	if !ok {
		return
	}

	switch err := h.zfs.UnloadKey(ctx, dataset); {
	case err == nil:
		// The dataset is now ciphertext. Evict the cached key too:
		// leaving it resident would keep tenant key material in daemon
		// memory for a container that is no longer running.
		h.cacheEvict(tenantFromRef(ref, containerName))
		log.Printf("[encryption] unloaded the key for %s; its dataset is now ciphertext at rest", containerName)
	case errors.Is(err, zfscrypt.ErrKeyInUse):
		// Another container under the same encryptionroot is still
		// running. Its key must stay loaded, and the cache entry stays
		// with it.
		log.Printf("[encryption] key for %s stays loaded: another container under the same encryptionroot is still running", containerName)
	default:
		log.Printf("[encryption] WARNING: could not unload the key for %s, so its dataset remains readable while stopped: %v",
			containerName, err)
	}
}

// RecordPlacement persists what the create produced: the key ref, and the
// storage pool whose source is the container's encryptionroot.
//
// The ref is written FIRST on purpose. A half-written record then leaves a
// container that refuses to start — encryptionRootFor says so explicitly —
// rather than one that reads as unencrypted. Encrypted-but-unstartable is
// legible and recoverable; silently-unencrypted is the failure #1294 exists
// to prevent.
func (h *encryptionHooks) RecordPlacement(containerName string, ref zfskey.KeyRef, pool string) error {
	if !h.enabled() {
		return fmt.Errorf("encryption is not configured on this daemon")
	}
	if pool == "" {
		return fmt.Errorf("refusing to record %s with no storage pool: its encryptionroot could not be resolved afterwards", containerName)
	}
	if err := h.refs.SetKeyRef(containerName, ref); err != nil {
		return fmt.Errorf("record the encryption key ref for %s: %w", containerName, err)
	}
	if err := h.refs.SetPool(containerName, pool); err != nil {
		return fmt.Errorf(
			"recorded the encryption key ref for %s but not its storage pool %s (%w) — the "+
				"container will refuse to start until the pool is recorded, which is deliberate: "+
				"it is encrypted and nothing can currently name its encryptionroot", containerName, pool, err)
	}
	return nil
}

func (h *encryptionHooks) cacheGet(tenant string) (zfskey.Key, bool) {
	if h.cache == nil {
		return zfskey.Key{}, false
	}
	return h.cache.Get(tenant)
}

func (h *encryptionHooks) cachePut(tenant string, k zfskey.Key) {
	if h.cache != nil {
		h.cache.Put(tenant, k)
	}
}

func (h *encryptionHooks) cacheEvict(tenant string) {
	if h.cache != nil {
		h.cache.Evict(tenant)
	}
}

// tenantFromRef derives the cache key for a ref. Falls back to the
// container name so a ref without tenant metadata still caches
// correctly, just less sharedly.
func tenantFromRef(ref zfskey.KeyRef, containerName string) string {
	if t := ref.Metadata["tenant"]; t != "" {
		return t
	}
	return containerName
}

// --- concrete adapters -----------------------------------------------

// incusEncryptionState persists a container's encryption state as Incus
// config keys on the container, so it survives a daemon restart — and
// reaches a migration destination — without the daemon holding any state of
// its own.
type incusEncryptionState struct {
	setConfig func(containerName, key, value string) error
	getConfig func(containerName, key string) (string, error)
	// listNames enumerates every container this daemon knows about. Only
	// rotation needs it (#1204) — the create, start and migration paths all
	// address one container by name.
	listNames func() ([]string, error)
}

func (s incusEncryptionState) GetKeyRef(containerName string) (zfskey.KeyRef, bool, error) {
	raw, err := s.getConfig(containerName, keyRefConfigKey)
	if err != nil {
		return zfskey.KeyRef{}, false, err
	}
	if raw == "" {
		return zfskey.KeyRef{}, false, nil
	}
	var ref zfskey.KeyRef
	if err := json.Unmarshal([]byte(raw), &ref); err != nil {
		return zfskey.KeyRef{}, false, fmt.Errorf("corrupt key ref on %s: %w", containerName, err)
	}
	return ref, true, nil
}

func (s incusEncryptionState) SetKeyRef(containerName string, ref zfskey.KeyRef) error {
	b, err := json.Marshal(ref)
	if err != nil {
		return fmt.Errorf("encode key ref: %w", err)
	}
	return s.setConfig(containerName, keyRefConfigKey, string(b))
}

func (s incusEncryptionState) GetPool(containerName string) (string, error) {
	return s.getConfig(containerName, poolConfigKey)
}

func (s incusEncryptionState) SetPool(containerName, pool string) error {
	return s.setConfig(containerName, poolConfigKey, pool)
}

// incusStoragePools adapts the daemon's Incus client to storagePoolAPI.
//
// Function values rather than a client, matching incusEncryptionState: it
// keeps this file free of a concrete Incus dependency, and lets the caller
// bind whichever client it already holds.
type incusStoragePools struct {
	createPool func(name, source string) error
	poolSource func(name string) (source string, exists bool, err error)
}

func (p incusStoragePools) CreateZFSPool(name, source string) error {
	return p.createPool(name, source)
}

func (p incusStoragePools) StoragePoolSource(name string) (string, bool, error) {
	return p.poolSource(name)
}

// ListEncrypted returns the containers carrying a key ref, so a rotation can
// be recorded against every container sharing an encryptionroot (#1204).
//
// Reads the ref rather than trusting a naming convention: a container is
// encrypted if and only if it records a key, which is the same test every
// other hook applies.
func (s incusEncryptionState) ListEncrypted() ([]string, error) {
	if s.listNames == nil {
		return nil, fmt.Errorf("this daemon cannot enumerate containers")
	}
	names, err := s.listNames()
	if err != nil {
		return nil, err
	}
	var encrypted []string
	for _, name := range names {
		raw, err := s.getConfig(name, keyRefConfigKey)
		if err != nil {
			// One unreadable container must not hide the rest; the caller
			// re-keys what it can see and the omission surfaces as that
			// container failing to start, which is loud.
			log.Printf("[encryption] could not read the key ref of %s while enumerating: %v", name, err)
			continue
		}
		if raw != "" {
			encrypted = append(encrypted, name)
		}
	}
	return encrypted, nil
}
