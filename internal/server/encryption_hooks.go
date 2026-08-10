package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

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

// keyRefStore reads and writes a container's durable KeyRef. An
// interface so the hooks are testable without Incus.
type keyRefStore interface {
	// GetKeyRef returns the stored ref and whether one was present.
	GetKeyRef(containerName string) (zfskey.KeyRef, bool, error)
	// SetKeyRef persists the ref on the container.
	SetKeyRef(containerName string, ref zfskey.KeyRef) error
}

// datasetResolver maps a container to the ZFS dataset backing it.
type datasetResolver interface {
	DatasetFor(containerName string) (string, error)
}

// encryptionHooks carries the collaborators the lifecycle hooks need.
// A nil *encryptionHooks is a valid no-op receiver, so call sites do not
// need to branch on whether encryption is configured.
type encryptionHooks struct {
	provider zfskey.KeyProvider
	zfs      *zfscrypt.Manager
	cache    *zfskey.Cache
	refs     keyRefStore
	datasets datasetResolver
}

// enabled reports whether encryption is wired at all.
func (h *encryptionHooks) enabled() bool {
	return h != nil && h.provider != nil && h.zfs != nil && h.refs != nil && h.datasets != nil
}

// encryptedFor returns the dataset and key ref for a container, and
// false when the container is not encrypted.
func (h *encryptionHooks) encryptedFor(containerName string) (dataset string, ref zfskey.KeyRef, ok bool, err error) {
	if !h.enabled() {
		return "", zfskey.KeyRef{}, false, nil
	}
	ref, present, err := h.refs.GetKeyRef(containerName)
	if err != nil || !present {
		return "", zfskey.KeyRef{}, false, err
	}
	dataset, err = h.datasets.DatasetFor(containerName)
	if err != nil {
		return "", zfskey.KeyRef{}, false, err
	}
	return dataset, ref, true, nil
}

// PreCreate provisions the encrypted dataset a new container will be
// built on, and returns the ref that lets every later hook re-resolve the
// same key.
//
// Order matters and is the whole of AC3. The key is resolved BEFORE
// anything is created, so a KeyProvider outage fails the create having
// touched nothing — there is no dataset to clean up because none was made.
// The only window where a partial dataset can exist is between creating it
// and persisting its ref, and that window is closed by destroying the
// dataset if the ref cannot be stored.
//
// That rollback is not tidiness. A dataset with no recorded ref is
// unopenable: nothing knows which key unlocks it, so it is neither usable
// nor safely reusable, and the next create for the same container would
// fail on a name that already exists. Leaking one is worse than failing.
func (h *encryptionHooks) PreCreate(ctx context.Context, containerName, tenant string) (zfskey.KeyRef, error) {
	if !h.enabled() {
		return zfskey.KeyRef{}, nil
	}
	if tenant == "" {
		return zfskey.KeyRef{}, fmt.Errorf("encryption: tenant is required to create %s", containerName)
	}

	dataset, err := h.datasets.DatasetFor(containerName)
	if err != nil {
		return zfskey.KeyRef{}, fmt.Errorf("resolve dataset for %s: %w", containerName, err)
	}

	// Wrap is per-tenant and idempotent: a tenant's containers share one
	// encryptionroot, so the second container reuses the first's key rather
	// than minting a second one that ZFS would treat as a separate root.
	key, ref, err := h.provider.Wrap(ctx, tenant)
	if err != nil {
		// Nothing has been created, so there is nothing to undo. The
		// create fails as Unavailable and the operator retries when key
		// custody is back.
		return zfskey.KeyRef{}, fmt.Errorf("cannot obtain an encryption key for %s: %w", containerName, err)
	}
	h.cachePut(tenant, key)

	if err := h.zfs.CreateEncrypted(ctx, dataset, key); err != nil {
		return zfskey.KeyRef{}, fmt.Errorf("cannot create the encrypted dataset for %s: %w", containerName, err)
	}

	if err := h.refs.SetKeyRef(containerName, ref); err != nil {
		// The dataset exists but nothing records how to unlock it. Undo it.
		if derr := h.zfs.Destroy(ctx, dataset); derr != nil {
			// Both failed: say so plainly, because now an operator has to
			// remove the dataset by hand before the name can be reused.
			return zfskey.KeyRef{}, fmt.Errorf(
				"could not record the encryption key ref for %s (%w), and rolling back its "+
					"dataset %s also failed (%v) — that dataset is unopenable and must be "+
					"destroyed manually before the name can be reused", containerName, err, dataset, derr)
		}
		return zfskey.KeyRef{}, fmt.Errorf("could not record the encryption key ref for %s: %w", containerName, err)
	}

	return ref, nil
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
	dataset, ref, ok, err := h.encryptedFor(containerName)
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
	dataset, ref, ok, err := h.encryptedFor(containerName)
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

// RecordKeyRef persists the ref produced at create time.
func (h *encryptionHooks) RecordKeyRef(containerName string, ref zfskey.KeyRef) error {
	if !h.enabled() {
		return fmt.Errorf("encryption is not configured on this daemon")
	}
	return h.refs.SetKeyRef(containerName, ref)
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

// incusKeyRefStore persists the KeyRef as an Incus config key on the
// container, so it survives a daemon restart without the daemon holding
// any state of its own.
type incusKeyRefStore struct {
	setConfig func(containerName, key, value string) error
	getConfig func(containerName, key string) (string, error)
}

func (s incusKeyRefStore) GetKeyRef(containerName string) (zfskey.KeyRef, bool, error) {
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

func (s incusKeyRefStore) SetKeyRef(containerName string, ref zfskey.KeyRef) error {
	b, err := json.Marshal(ref)
	if err != nil {
		return fmt.Errorf("encode key ref: %w", err)
	}
	return s.setConfig(containerName, keyRefConfigKey, string(b))
}
