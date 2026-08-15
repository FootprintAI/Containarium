package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// --- fakes -----------------------------------------------------------

type fakeKeyProvider struct {
	key      zfskey.Key
	loadErr  error
	loadCall int
	wrapErr  error
	wrapCall int
	// wrapped records the tenants Wrap was called for, in order.
	wrapped []string
}

func (f *fakeKeyProvider) Wrap(_ context.Context, tenant string) (zfskey.Key, zfskey.KeyRef, error) {
	f.wrapCall++
	if f.wrapErr != nil {
		return zfskey.Key{}, zfskey.KeyRef{}, f.wrapErr
	}
	f.wrapped = append(f.wrapped, tenant)
	// Per-tenant URI, matching the real contract: a tenant's containers
	// share one key, and two tenants never do.
	uri := "/keys/" + tenant + ".key"
	if tenant == "" {
		uri = "/keys/alice.key"
	}
	return f.key, zfskey.KeyRef{Scheme: zfskey.SchemeFile, URI: uri}, nil
}

func (f *fakeKeyProvider) Load(context.Context, zfskey.KeyRef) (zfskey.Key, error) {
	f.loadCall++
	if f.loadErr != nil {
		return zfskey.Key{}, f.loadErr
	}
	return f.key, nil
}

type fakeRefStore struct {
	refs  map[string]zfskey.KeyRef
	pools map[string]string
	err   error
	// setErr fails only writes, which is the window EnsureTenantStorage has
	// to roll back: the dataset exists but nothing records how to unlock it.
	setErr error
}

func (f *fakeRefStore) GetKeyRef(name string) (zfskey.KeyRef, bool, error) {
	if f.err != nil {
		return zfskey.KeyRef{}, false, f.err
	}
	ref, ok := f.refs[name]
	return ref, ok, nil
}

func (f *fakeRefStore) SetKeyRef(name string, ref zfskey.KeyRef) error {
	if f.setErr != nil {
		return f.setErr
	}
	if f.err != nil {
		return f.err
	}
	f.refs[name] = ref
	return nil
}

func (f *fakeRefStore) GetPool(name string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.pools[name], nil
}

func (f *fakeRefStore) SetPool(name, pool string) error {
	if f.setErr != nil {
		return f.setErr
	}
	if f.err != nil {
		return f.err
	}
	if f.pools == nil {
		f.pools = map[string]string{}
	}
	f.pools[name] = pool
	return nil
}

// ListEncrypted lets the rotation path enumerate the containers sharing an
// encryptionroot (#1204).
func (f *fakeRefStore) ListEncrypted() ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	names := make([]string, 0, len(f.refs))
	for name := range f.refs {
		names = append(names, name)
	}
	return names, nil
}

// fakePools stands in for the Incus storage-pool API. It records what was
// created so a test can tell "reused an existing pool" from "made a second
// one" — the difference between a tenant having one encryptionroot and two.
type fakePools struct {
	sources   map[string]string
	created   []string
	createErr error
	sourceErr error
}

func newFakePools() *fakePools { return &fakePools{sources: map[string]string{}} }

func (f *fakePools) CreateZFSPool(name, source string) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, name)
	f.sources[name] = source
	return nil
}

func (f *fakePools) StoragePoolSource(name string) (string, bool, error) {
	if f.sourceErr != nil {
		return "", false, f.sourceErr
	}
	src, ok := f.sources[name]
	return src, ok, nil
}

// zfsFake records commands and replays canned results, keyed by
// subcommand.
type zfsFake struct {
	calls  []string
	stdout map[string]string
	errs   map[string]error
	stderr map[string]string
}

func newZFSFake() *zfsFake {
	return &zfsFake{
		stdout: map[string]string{"get": "unavailable"},
		// `zfs list` fails for a dataset that is not there, which is how
		// zfscrypt.Exists tells absent from present. Absent is the default
		// because a tenant's FIRST encrypted container is the case that has
		// to create everything.
		errs:   map[string]error{"list": errors.New("exit status 1")},
		stderr: map[string]string{"list": "cannot open 'x': dataset does not exist"},
	}
}

// datasetPresent makes the tenant encryptionroot look already-provisioned,
// reporting encryptionRoot as its `zfs get encryptionroot` value. Pass the
// dataset itself for a properly encrypted root, or "-" for a plaintext one.
func (z *zfsFake) datasetPresent(encryptionRoot string) {
	delete(z.errs, "list")
	z.stdout["list"] = "present"
	z.stdout["get"] = encryptionRoot
}

func (z *zfsFake) Run(_ context.Context, _ []byte, args ...string) (string, string, error) {
	z.calls = append(z.calls, strings.Join(args, " "))
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	return z.stdout[sub], z.stderr[sub], z.errs[sub]
}

func (z *zfsFake) ran(substr string) bool {
	for _, c := range z.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func testHooks(t *testing.T, z *zfsFake, p *fakeKeyProvider, refs map[string]zfskey.KeyRef) *encryptionHooks {
	t.Helper()
	// Every container in refs is placed on its tenant's pool, because that
	// is what the create path records — PreStart resolves the encryptionroot
	// through it, and a container with a ref and no pool is a half-written
	// record the hooks deliberately refuse (see encryptionRootFor).
	placed := map[string]string{}
	pools := newFakePools()
	for name := range refs {
		tenant := strings.TrimSuffix(name, "-container")
		placed[name] = tenantPoolName(tenant)
		pools.sources[tenantPoolName(tenant)] = "tank/tenants/" + tenant
	}
	return &encryptionHooks{
		provider:   p,
		zfs:        zfscrypt.NewManager(z),
		cache:      zfskey.NewCache(time.Hour),
		refs:       &fakeRefStore{refs: refs, pools: placed},
		pools:      pools,
		tenantRoot: "tank/tenants",
	}
}

func aKey(t *testing.T) zfskey.Key {
	t.Helper()
	k, err := zfskey.NewKey(bytes.Repeat([]byte{7}, zfskey.KeyLen))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

// --- unencrypted containers are untouched ----------------------------

// The default path must be completely unchanged: today every container
// is unencrypted, and the hooks must not run a single zfs command
// against them.
func TestHooksAreNoOpsForUnencryptedContainers(t *testing.T) {
	z := newZFSFake()
	h := testHooks(t, z, &fakeKeyProvider{key: aKey(t)}, map[string]zfskey.KeyRef{})

	if err := h.PreStart(context.Background(), "alice-container"); err != nil {
		t.Fatalf("PreStart on an unencrypted container: %v", err)
	}
	h.PostStop(context.Background(), "alice-container")

	if len(z.calls) != 0 {
		t.Errorf("zfs was invoked for an unencrypted container: %v", z.calls)
	}
}

// A daemon with no encryption configured at all must behave the same.
func TestNilHooksAreSafe(t *testing.T) {
	var h *encryptionHooks
	if err := h.PreStart(context.Background(), "alice-container"); err != nil {
		t.Errorf("PreStart on a nil hooks receiver: %v", err)
	}
	h.PostStop(context.Background(), "alice-container") // must not panic
}

// --- pre-start (#1199) -----------------------------------------------

func TestPreStartLoadsTheKey(t *testing.T) {
	z := newZFSFake()
	p := &fakeKeyProvider{key: aKey(t)}
	h := testHooks(t, z, p, map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"},
	})

	if err := h.PreStart(context.Background(), "alice-container"); err != nil {
		t.Fatalf("PreStart: %v", err)
	}
	if !z.ran("load-key") {
		t.Errorf("load-key never ran: %v", z.calls)
	}
	// The encryptionroot is the tenant's dataset — the pool's source — not
	// the container's own, which inherits the key and has none to load.
	if !z.ran("tank/tenants/alice") {
		t.Errorf("acted on the wrong dataset: %v", z.calls)
	}
}

// AC (#1199): KeyProvider down at start time → the start fails and the
// container stays stopped.
//
// Booting anyway would give the tenant a container whose storage
// silently is not there, which is worse than a refused start.
func TestPreStartFailsWhenTheKeyCannotBeLoaded(t *testing.T) {
	z := newZFSFake()
	p := &fakeKeyProvider{key: aKey(t), loadErr: errors.New("KMS unreachable")}
	h := testHooks(t, z, p, map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"},
	})

	err := h.PreStart(context.Background(), "alice-container")
	if err == nil {
		t.Fatal("PreStart succeeded with no key — the container would boot with unreadable storage")
	}
	if !strings.Contains(err.Error(), "KMS unreachable") {
		t.Errorf("the custody error should survive, got %q", err)
	}
	if z.ran("load-key") {
		t.Error("load-key ran despite having no key")
	}
}

// A daemon restart re-runs pre-start; the cache is empty then, so the
// key is re-fetched from the provider rather than the start failing.
func TestPreStartRefetchesAfterARestart(t *testing.T) {
	refs := map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"},
	}
	p := &fakeKeyProvider{key: aKey(t)}

	h1 := testHooks(t, newZFSFake(), p, refs)
	if err := h1.PreStart(context.Background(), "alice-container"); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if p.loadCall != 1 {
		t.Fatalf("provider Load calls = %d, want 1", p.loadCall)
	}

	// Same hooks instance: the cache should serve the second start.
	if err := h1.PreStart(context.Background(), "alice-container"); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if p.loadCall != 1 {
		t.Errorf("provider was re-queried despite a warm cache (calls=%d)", p.loadCall)
	}

	// A fresh process (new hooks, new cache) must go back to the provider.
	h2 := testHooks(t, newZFSFake(), p, refs)
	if err := h2.PreStart(context.Background(), "alice-container"); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if p.loadCall != 2 {
		t.Errorf("a restarted daemon must re-fetch from the provider, calls=%d", p.loadCall)
	}
}

// --- post-stop (#1201) -----------------------------------------------

// The headline behaviour of #1201: stopping unloads the key, so the
// dataset is ciphertext at rest.
func TestPostStopUnloadsTheKey(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = "available"
	h := testHooks(t, z, &fakeKeyProvider{key: aKey(t)}, map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"},
	})

	h.PostStop(context.Background(), "alice-container")

	if !z.ran("unload-key") {
		t.Errorf("unload-key never ran — a stopped container's dataset stays readable: %v", z.calls)
	}
}

// AC (#1201): stopping one of several containers under the same
// encryptionroot must NOT unload the key, and must not be treated as a
// failure.
func TestPostStopToleratesAKeyStillInUse(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = "available"
	z.errs["unload-key"] = errors.New("exit status 1")
	z.stderr["unload-key"] = "cannot unload key: dataset is busy"

	h := testHooks(t, z, &fakeKeyProvider{key: aKey(t)}, map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key",
			Metadata: map[string]string{"tenant": "alice"}},
	})

	// Warm the cache so we can assert it is NOT evicted.
	h.cachePut("alice", aKey(t))

	h.PostStop(context.Background(), "alice-container") // must not panic or block

	if _, ok := h.cacheGet("alice"); !ok {
		t.Error("the tenant's cached key was evicted while another of their containers is still running")
	}
}

// A successful unload evicts the cached key: leaving it resident would
// keep tenant key material in daemon memory for a container that is no
// longer running.
func TestPostStopEvictsTheCachedKeyOnSuccess(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = "available"
	h := testHooks(t, z, &fakeKeyProvider{key: aKey(t)}, map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key",
			Metadata: map[string]string{"tenant": "alice"}},
	})
	h.cachePut("alice", aKey(t))

	h.PostStop(context.Background(), "alice-container")

	if _, ok := h.cacheGet("alice"); ok {
		t.Error("key stayed cached after a successful unload")
	}
}

// PostStop never fails the RPC: the container has already stopped, so
// reporting a failure would call a stop that happened a failure.
func TestPostStopDoesNotPropagateFailures(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = "available"
	z.errs["unload-key"] = errors.New("exit status 1")
	z.stderr["unload-key"] = "permission denied"

	h := testHooks(t, z, &fakeKeyProvider{key: aKey(t)}, map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"},
	})

	// Signature returns nothing: a stop cannot be undone by a failed
	// unload, so there is no error for the caller to act on. The
	// operator learns from the log.
	h.PostStop(context.Background(), "alice-container")
}

// --- durable encryption state ----------------------------------------

// Both halves must round-trip through the store: a restarted daemon
// re-resolves the key from the ref and the encryptionroot from the pool,
// and holds no state itself.
func TestKeyRefRoundTrips(t *testing.T) {
	stored := map[string]string{}
	s := incusEncryptionState{
		setConfig: func(_, k, v string) error { stored[k] = v; return nil },
		getConfig: func(_, k string) (string, error) { return stored[k], nil },
	}

	want := zfskey.KeyRef{
		Scheme:   zfskey.SchemeFile,
		URI:      "/etc/containarium/keys/alice.key",
		Metadata: map[string]string{"tenant": "alice"},
	}
	if err := s.SetKeyRef("alice-container", want); err != nil {
		t.Fatalf("SetKeyRef: %v", err)
	}
	got, ok, err := s.GetKeyRef("alice-container")
	if err != nil || !ok {
		t.Fatalf("GetKeyRef: %v ok=%v", err, ok)
	}
	if got.Scheme != want.Scheme || got.URI != want.URI || got.Metadata["tenant"] != "alice" {
		t.Errorf("round trip lost data: %+v", got)
	}

	// A container with no ref is simply unencrypted, not an error.
	empty := incusEncryptionState{
		setConfig: func(string, string, string) error { return nil },
		getConfig: func(string, string) (string, error) { return "", nil },
	}
	if _, ok, err := empty.GetKeyRef("bob-container"); err != nil || ok {
		t.Errorf("absent ref: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// The pool travels the same way, under its own key, so the two are
	// independently readable — a container can be found to have a ref and no
	// pool, which encryptionRootFor refuses rather than papers over.
	if err := s.SetPool("alice-container", "containarium-tenant-alice"); err != nil {
		t.Fatalf("SetPool: %v", err)
	}
	gotPool, err := s.GetPool("alice-container")
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if gotPool != "containarium-tenant-alice" {
		t.Errorf("pool round trip = %q, want %q", gotPool, "containarium-tenant-alice")
	}
	if stored[keyRefConfigKey] == "" || stored[poolConfigKey] == "" {
		t.Errorf("the two halves did not land under distinct config keys: %v", stored)
	}
}

// A corrupt ref is an error, not a silently unencrypted container —
// otherwise a mangled config key would downgrade a tenant to plaintext
// handling without anyone noticing.
func TestCorruptKeyRefIsAnError(t *testing.T) {
	s := incusEncryptionState{
		setConfig: func(string, string, string) error { return nil },
		getConfig: func(string, string) (string, error) { return "{not json", nil },
	}
	if _, _, err := s.GetKeyRef("alice-container"); err == nil {
		t.Error("a corrupt key ref must not be read as 'no encryption'")
	}
}

// --- PreCreate (#1199) -------------------------------------------------

// sameRef compares the identity of two refs. KeyRef carries a Metadata map,
// so it is not comparable with ==; Scheme and URI are what identify the key.
func sameRef(a, b zfskey.KeyRef) bool {
	return a.Scheme == b.Scheme && a.URI == b.URI
}

// testHooksWith is testHooks with a ref store and pool API the caller can
// break.
func testHooksWith(t *testing.T, z *zfsFake, p *fakeKeyProvider, refs *fakeRefStore, pools *fakePools) *encryptionHooks {
	t.Helper()
	if refs.pools == nil {
		refs.pools = map[string]string{}
	}
	if pools == nil {
		pools = newFakePools()
	}
	return &encryptionHooks{
		provider:   p,
		zfs:        zfscrypt.NewManager(z),
		cache:      zfskey.NewCache(time.Hour),
		refs:       refs,
		pools:      pools,
		tenantRoot: "tank/tenants",
	}
}

// --- EnsureTenantStorage (#1340) --------------------------------------
//
// PreCreate provisioned a per-CONTAINER encrypted dataset and pointed Incus
// at it. Incus cannot use one: it builds an instance by cloning the image
// snapshot, and a ZFS clone inherits encryption from its origin rather than
// its location (#1335). So the hook provisions a per-TENANT encrypted dataset
// and an Incus pool sourced at it, and the create targets that pool —
// everything Incus makes inside it inherits the tenant's key.
//
// These tests pin orchestration: what runs, in what order, and what is left
// behind when a step fails. The encryption properties they exist to protect
// are ZFS's to compute and are asserted against a real pool.

func TestEnsureTenantStorage_CreatesTheDatasetAndThePoolOnIt(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	pools := newFakePools()

	pool, ref, err := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools).
		EnsureTenantStorage(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureTenantStorage: %v", err)
	}

	if !z.ran("create") || !z.ran("encryption=on") {
		t.Errorf("no encrypted dataset was created; calls=%v", z.calls)
	}
	if !z.ran("tank/tenants/alice") {
		t.Errorf("the tenant encryptionroot was not created; calls=%v", z.calls)
	}
	if pool == "" {
		t.Fatal("no pool name returned — the create has nothing to place the container on")
	}
	if got := pools.sources[pool]; got != "tank/tenants/alice" {
		t.Errorf("pool %q is sourced at %q, want the tenant's encryptionroot %q — a pool "+
			"sourced anywhere else gives its containers no key at all", pool, got, "tank/tenants/alice")
	}
	if ref.URI == "" {
		t.Error("no key ref returned; nothing could re-resolve the key later")
	}
}

// A tenant's containers share one encryptionroot, and two tenants never do.
// The second container for a tenant must reuse — not re-create, and above all
// not re-key — what the first one made.
func TestEnsureTenantStorage_IsIdempotentForASecondContainer(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	pools := newFakePools()
	h := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools)
	ctx := context.Background()

	first, firstRef, err := h.EnsureTenantStorage(ctx, "alice")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// The dataset now exists, which is what the second call must notice.
	z.datasetPresent("tank/tenants/alice")

	second, secondRef, err := h.EnsureTenantStorage(ctx, "alice")
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if second != first {
		t.Errorf("the same tenant's two containers got pools %q and %q — they would sit under "+
			"separate encryptionroots", first, second)
	}
	if !sameRef(firstRef, secondRef) {
		t.Errorf("the same tenant got two key refs (%v vs %v)", firstRef, secondRef)
	}
	if len(pools.created) != 1 {
		t.Errorf("the pool was created %d times, want 1 — a second create for a tenant that "+
			"already has storage is how one tenant ends up with two encryptionroots", len(pools.created))
	}
}

func TestEnsureTenantStorage_KeysPerTenantNotPerContainer(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	h := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, nil)
	ctx := context.Background()

	alice, aliceRef, err := h.EnsureTenantStorage(ctx, "alice")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, bobRef, err := h.EnsureTenantStorage(ctx, "bob")
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	if alice == bob {
		t.Errorf("two tenants share pool %q — one tenant's key would unlock the other's data, "+
			"which is the whole boundary this design exists to draw", alice)
	}
	if sameRef(aliceRef, bobRef) {
		t.Errorf("two tenants share a key ref (%v)", aliceRef)
	}
	for _, tenant := range p.wrapped {
		if tenant != "alice" && tenant != "bob" {
			t.Errorf("Wrap was called for %q, not a tenant", tenant)
		}
	}
}

// #1199 AC3. The key is resolved first precisely so a provider outage fails
// having touched nothing — there is no dataset to clean up because none was
// made, and no pool either.
func TestEnsureTenantStorage_ResolvesTheKeyBeforeCreatingAnything(t *testing.T) {
	z := newZFSFake()
	p := &fakeKeyProvider{key: aKey(t), wrapErr: errors.New("kms unreachable")}
	pools := newFakePools()

	_, _, err := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools).
		EnsureTenantStorage(context.Background(), "alice")
	if err == nil {
		t.Fatal("EnsureTenantStorage succeeded with the key provider down")
	}
	if z.ran("create") {
		t.Errorf("a dataset was created despite having no key; calls=%v", z.calls)
	}
	if len(pools.created) != 0 {
		t.Errorf("a storage pool was created despite having no key: %v", pools.created)
	}
}

// The rollback asymmetry, and the reason this issue carried a warning.
//
// PreCreate destroyed the dataset whenever the follow-up step failed, which
// was right when the dataset belonged to one container. It is now the
// TENANT's encryptionroot, shared by every container they own. Destroying it
// because an unrelated container's create failed would destroy live data.
//
// So: roll back only what this call created.
func TestEnsureTenantStorage_RollsBackOnlyADatasetItCreated(t *testing.T) {
	t.Run("a dataset this call created is destroyed when the pool cannot be made", func(t *testing.T) {
		z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
		pools := newFakePools()
		pools.createErr = errors.New("incus unreachable")

		_, _, err := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools).
			EnsureTenantStorage(context.Background(), "alice")
		if err == nil {
			t.Fatal("EnsureTenantStorage succeeded with no pool")
		}
		if !z.ran("destroy") {
			t.Errorf("a dataset with no pool on it was left behind; calls=%v — nothing "+
				"references it and the next attempt fails on a name that already exists", z.calls)
		}
	})

	t.Run("a dataset that already existed is left alone", func(t *testing.T) {
		z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
		// The tenant's encryptionroot is already there, from an earlier
		// container that is very possibly running right now.
		z.datasetPresent("tank/tenants/alice")
		pools := newFakePools()
		pools.createErr = errors.New("incus unreachable")

		_, _, err := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools).
			EnsureTenantStorage(context.Background(), "alice")
		if err == nil {
			t.Fatal("EnsureTenantStorage succeeded with no pool")
		}
		if z.ran("destroy") {
			t.Fatalf("the tenant's existing encryptionroot was DESTROYED because one "+
				"container's create failed; calls=%v — every other container that tenant "+
				"owns just lost its storage", z.calls)
		}
	})
}

// A pool name that is taken by a pool pointing somewhere else is not ours to
// reuse and not ours to repoint. Repointing would move an existing pool's
// containers onto a different encryptionroot underneath them.
func TestEnsureTenantStorage_RefusesAPoolPointingSomewhereElse(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	pools := newFakePools()
	h := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools)

	// Whatever pool name the hook derives, it is already taken by a pool on
	// somebody else's dataset.
	pools.sources[tenantPoolName("alice")] = "tank/somewhere/else"

	if _, _, err := h.EnsureTenantStorage(context.Background(), "alice"); err == nil {
		t.Fatal("a storage pool sourced at another dataset was silently reused — the tenant's " +
			"containers would land outside the encryptionroot the daemon just recorded for them")
	}
	if pools.sources[tenantPoolName("alice")] != "tank/somewhere/else" {
		t.Error("the existing pool was repointed; its current containers would be moved onto a " +
			"different encryptionroot underneath them")
	}
}

// A dataset already at the tenant's path but NOT encrypted is the quietest
// possible failure: the pool would be built on plaintext and every container
// on it reported as encrypted.
func TestEnsureTenantStorage_RefusesAnExistingPlaintextDataset(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	// `zfs get encryptionroot` reports "-" for an unencrypted dataset.
	z.datasetPresent("-")
	pools := newFakePools()

	_, _, err := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools).
		EnsureTenantStorage(context.Background(), "alice")
	if err == nil {
		t.Fatal("an unencrypted dataset was accepted as a tenant encryptionroot — the pool " +
			"would be built on plaintext and its containers reported as encrypted")
	}
	if len(pools.created) != 0 {
		t.Errorf("a pool was created on an unencrypted dataset: %v", pools.created)
	}
}

func TestEnsureTenantStorage_RequiresAUsableTenantName(t *testing.T) {
	for _, tenant := range []string{"", "../escape", "a/b", "-flag", "with space", "."} {
		t.Run("tenant="+tenant, func(t *testing.T) {
			z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
			pools := newFakePools()

			_, _, err := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools).
				EnsureTenantStorage(context.Background(), tenant)
			if err == nil {
				t.Errorf("tenant %q was accepted — it is interpolated into a ZFS dataset path "+
					"and an Incus pool name, so it must not be able to name something else", tenant)
			}
			if z.ran("create") || len(pools.created) != 0 {
				t.Errorf("something was created for an invalid tenant; calls=%v pools=%v",
					z.calls, pools.created)
			}
		})
	}
}

// Encryption unconfigured must not fail a create — the flag defaults off and
// existing deployments keep working.
func TestEnsureTenantStorage_NoOpWhenEncryptionIsNotConfigured(t *testing.T) {
	var h *encryptionHooks
	pool, ref, err := h.EnsureTenantStorage(context.Background(), "alice")
	if err != nil {
		t.Errorf("a nil hooks receiver failed the create: %v", err)
	}
	if pool != "" || ref.URI != "" {
		t.Errorf("returned placement with no provider configured: pool=%q ref=%v", pool, ref)
	}
}

// --- placement is recorded so a restarted daemon can find the key ------

func TestRecordPlacement_StoresBothTheRefAndThePool(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}}
	h := testHooksWith(t, z, p, refs, nil)

	ref := zfskey.KeyRef{Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"}
	if err := h.RecordPlacement("alice-container", ref, "containarium-tenant-alice"); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}

	if !sameRef(refs.refs["alice-container"], ref) {
		t.Errorf("stored ref %v, want %v", refs.refs["alice-container"], ref)
	}
	if refs.pools["alice-container"] != "containarium-tenant-alice" {
		t.Errorf("stored pool %q, want %q — without it the daemon cannot find the container's "+
			"encryptionroot after a restart", refs.pools["alice-container"], "containarium-tenant-alice")
	}
}

// The ref is written before the pool, so a half-written record leaves a
// container that REFUSES to start rather than one treated as unencrypted.
// Encrypted-but-unstartable is legible and recoverable; silently-unencrypted
// is the failure #1294 exists to prevent.
func TestRecordPlacement_APartialWriteFailsClosed(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}, setErr: errors.New("incus unreachable")}
	h := testHooksWith(t, z, p, refs, nil)

	if err := h.RecordPlacement("alice-container", zfskey.KeyRef{Scheme: zfskey.SchemeFile, URI: "/k"}, "p"); err == nil {
		t.Fatal("a failed placement write was reported as success")
	}
}

// A container carrying a key ref but no pool cannot have its encryptionroot
// resolved. It must refuse to start, and say why — treating it as
// unencrypted would start it on storage nobody can account for.
func TestPreStart_RefusesAContainerWithARefButNoPool(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{
		refs:  map[string]zfskey.KeyRef{"alice-container": {Scheme: zfskey.SchemeFile, URI: "/k"}},
		pools: map[string]string{}, // no pool recorded
	}

	err := testHooksWith(t, z, p, refs, nil).PreStart(context.Background(), "alice-container")
	if err == nil {
		t.Fatal("a container with an encryption key ref and no recorded pool was started — " +
			"nothing knows which dataset to unlock, so it would run on storage the daemon " +
			"cannot account for")
	}
	if !strings.Contains(err.Error(), "pool") {
		t.Errorf("the error does not name the missing pool, so an operator cannot act on it: %v", err)
	}
}

// PreStart loads the key on the tenant's encryptionroot — the pool's source
// dataset — not on the container's own dataset, which inherits it and has no
// key of its own to load.
func TestPreStart_LoadsTheKeyOnThePoolRootNotTheContainer(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{
		refs:  map[string]zfskey.KeyRef{"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"}},
		pools: map[string]string{"alice-container": "containarium-tenant-alice"},
	}
	pools := newFakePools()
	pools.sources["containarium-tenant-alice"] = "tank/tenants/alice"

	if err := testHooksWith(t, z, p, refs, pools).PreStart(context.Background(), "alice-container"); err != nil {
		t.Fatalf("PreStart: %v", err)
	}

	if !z.ran("load-key") {
		t.Fatalf("no key was loaded; calls=%v", z.calls)
	}
	if !z.ran("tank/tenants/alice") {
		t.Errorf("the key was loaded on the wrong dataset; calls=%v — the encryptionroot is the "+
			"pool's source, and the container's own dataset has no key to load", z.calls)
	}
	if z.ran("alice-container") {
		t.Errorf("a zfs command named the container dataset; calls=%v", z.calls)
	}
}

// The pool adapter is bound to whichever Incus client the daemon already
// holds, so what needs pinning is that it passes both arguments through
// untouched — a source that arrives altered points the tenant pool at the
// wrong dataset, which is how a container ends up unencrypted while every
// daemon-side signal says otherwise (#1336 was that class of bug).
func TestIncusStoragePoolsPassesItsArgumentsThrough(t *testing.T) {
	var gotName, gotSource string
	p := incusStoragePools{
		createPool: func(name, source string) error { gotName, gotSource = name, source; return nil },
		poolSource: func(name string) (string, bool, error) { return "tank/tenants/" + name, true, nil },
	}

	if err := p.CreateZFSPool("containarium-tenant-alice", "tank/tenants/alice"); err != nil {
		t.Fatalf("CreateZFSPool: %v", err)
	}
	if gotName != "containarium-tenant-alice" || gotSource != "tank/tenants/alice" {
		t.Errorf("passed through (%q, %q), want (%q, %q)",
			gotName, gotSource, "containarium-tenant-alice", "tank/tenants/alice")
	}

	src, exists, err := p.StoragePoolSource("alice")
	if err != nil || !exists || src != "tank/tenants/alice" {
		t.Errorf("StoragePoolSource = (%q, %v, %v)", src, exists, err)
	}
}

// --- naming ------------------------------------------------------------

func TestTenantDataset(t *testing.T) {
	for _, tc := range []struct {
		name, root, tenant, want string
		wantErr                  bool
	}{
		{name: "nested root", root: "tank/tenants", tenant: "alice", want: "tank/tenants/alice"},
		{name: "trailing slash is tolerated", root: "tank/tenants/", tenant: "alice", want: "tank/tenants/alice"},
		{name: "empty root", root: "", tenant: "alice", wantErr: true},
		{name: "bare pool root", root: "tank", tenant: "alice", want: "tank/alice"},
		{name: "empty tenant", root: "tank/tenants", tenant: "", wantErr: true},
		{name: "tenant with a slash", root: "tank/tenants", tenant: "a/b", wantErr: true},
		{name: "tenant escaping upward", root: "tank/tenants", tenant: "..", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tenantDataset(tc.root, tc.tenant)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("tenantDataset(%q, %q) = %q, want an error", tc.root, tc.tenant, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("tenantDataset(%q, %q): %v", tc.root, tc.tenant, err)
			}
			if got != tc.want {
				t.Errorf("tenantDataset(%q, %q) = %q, want %q", tc.root, tc.tenant, got, tc.want)
			}
		})
	}
}

func TestTenantPoolName_IsStableAndTenantScoped(t *testing.T) {
	alice, bob := tenantPoolName("alice"), tenantPoolName("bob")
	if alice == bob {
		t.Fatalf("two tenants derive the same pool name %q", alice)
	}
	if alice != tenantPoolName("alice") {
		t.Error("the pool name is not stable across calls — a restarted daemon would not find " +
			"the pool it created")
	}
	if !strings.Contains(alice, "alice") {
		t.Errorf("pool name %q does not identify the tenant, which makes an operator's `incus "+
			"storage list` unreadable", alice)
	}
}
