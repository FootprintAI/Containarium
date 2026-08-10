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
	refs map[string]zfskey.KeyRef
	err  error
	// setErr fails only writes, which is the window PreCreate has to roll
	// back: the dataset exists but nothing records how to unlock it.
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

type fakeDatasets struct{ prefix string }

func (f fakeDatasets) DatasetFor(name string) (string, error) {
	return f.prefix + "/" + name, nil
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
		errs:   map[string]error{},
		stderr: map[string]string{},
	}
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
	return &encryptionHooks{
		provider: p,
		zfs:      zfscrypt.NewManager(z),
		cache:    zfskey.NewCache(time.Hour),
		refs:     &fakeRefStore{refs: refs},
		datasets: fakeDatasets{prefix: "pool/containers"},
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
	if !z.ran("pool/containers/alice-container") {
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

// --- key ref persistence ---------------------------------------------

// The ref must round-trip through the store, since a restarted daemon
// re-resolves the key from it and holds no state itself.
func TestKeyRefRoundTrips(t *testing.T) {
	stored := map[string]string{}
	s := incusKeyRefStore{
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
	empty := incusKeyRefStore{
		setConfig: func(string, string, string) error { return nil },
		getConfig: func(string, string) (string, error) { return "", nil },
	}
	if _, ok, err := empty.GetKeyRef("bob-container"); err != nil || ok {
		t.Errorf("absent ref: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

// A corrupt ref is an error, not a silently unencrypted container —
// otherwise a mangled config key would downgrade a tenant to plaintext
// handling without anyone noticing.
func TestCorruptKeyRefIsAnError(t *testing.T) {
	s := incusKeyRefStore{
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

// testHooksWith is testHooks with a ref store the caller can break.
func testHooksWith(t *testing.T, z *zfsFake, p *fakeKeyProvider, refs *fakeRefStore) *encryptionHooks {
	t.Helper()
	return &encryptionHooks{
		provider: p,
		zfs:      zfscrypt.NewManager(z),
		cache:    zfskey.NewCache(time.Hour),
		refs:     refs,
		datasets: fakeDatasets{prefix: "pool/containers"},
	}
}

func TestPreCreate_CreatesAnEncryptedDatasetAndRecordsItsRef(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}}

	ref, err := testHooksWith(t, z, p, refs).PreCreate(context.Background(), "alice-container", "alice")
	if err != nil {
		t.Fatalf("PreCreate: %v", err)
	}

	if !z.ran("create") || !z.ran("encryption=on") {
		t.Errorf("no encrypted dataset was created; calls=%v", z.calls)
	}
	if !z.ran("pool/containers/alice-container") {
		t.Errorf("created the wrong dataset; calls=%v", z.calls)
	}
	if !sameRef(refs.refs["alice-container"], ref) {
		t.Errorf("stored ref %v, returned %v — every later hook re-resolves the key from the "+
			"stored one, so a mismatch means the container cannot be started",
			refs.refs["alice-container"], ref)
	}
}

// A tenant's containers share one encryptionroot, and two tenants never do.
// Wrap is what guarantees it, so PreCreate must ask per tenant — not per
// container, which would mint a second key and a second root for the same
// tenant.
func TestPreCreate_KeysPerTenantNotPerContainer(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}}
	h := testHooksWith(t, z, p, refs)
	ctx := context.Background()

	first, err := h.PreCreate(ctx, "alice-one", "alice")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := h.PreCreate(ctx, "alice-two", "alice")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	other, err := h.PreCreate(ctx, "bob-one", "bob")
	if err != nil {
		t.Fatalf("other tenant: %v", err)
	}

	if !sameRef(first, second) {
		t.Errorf("the same tenant's two containers got different key refs (%v vs %v) — they "+
			"would sit under separate encryptionroots", first, second)
	}
	if sameRef(other, first) {
		t.Errorf("two tenants share a key ref (%v) — one tenant's key would unlock another's "+
			"data, which is the whole boundary this design exists to draw", other)
	}
	for _, tenant := range p.wrapped {
		if tenant != "alice" && tenant != "bob" {
			t.Errorf("Wrap was called for %q, not a tenant", tenant)
		}
	}
}

// AC3: KeyProvider down at create time must leave nothing behind. The key is
// resolved first precisely so there is nothing to clean up.
func TestPreCreate_KeyProviderDownCreatesNothing(t *testing.T) {
	z := newZFSFake()
	p := &fakeKeyProvider{key: aKey(t), wrapErr: errors.New("kms unreachable")}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}}

	_, err := testHooksWith(t, z, p, refs).PreCreate(context.Background(), "alice-container", "alice")
	if err == nil {
		t.Fatal("PreCreate succeeded with the key provider down")
	}
	if z.ran("create") {
		t.Errorf("a dataset was created despite having no key; calls=%v — it would be "+
			"unopenable and would block the name on retry", z.calls)
	}
	if len(refs.refs) != 0 {
		t.Errorf("a key ref was recorded for a container that was never created: %v", refs.refs)
	}
}

// The one window where a partial dataset can exist: created, but its ref not
// recorded. Nothing knows which key unlocks it, so it is neither usable nor
// safely reusable — it must be destroyed.
func TestPreCreate_RollsBackTheDatasetWhenTheRefCannotBeStored(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}, setErr: errors.New("incus unreachable")}

	_, err := testHooksWith(t, z, p, refs).PreCreate(context.Background(), "alice-container", "alice")
	if err == nil {
		t.Fatal("PreCreate succeeded without recording the key ref")
	}
	if !z.ran("destroy") {
		t.Errorf("the dataset was left behind with no recorded key; calls=%v — nothing can "+
			"unlock it and the next create fails on a name that already exists", z.calls)
	}
}

// When the rollback itself fails, the error has to say so — an operator now
// has to remove the dataset by hand before the name can be reused.
func TestPreCreate_SaysSoWhenTheRollbackAlsoFails(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	z.errs["destroy"] = errors.New("dataset busy")
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}, setErr: errors.New("incus unreachable")}

	_, err := testHooksWith(t, z, p, refs).PreCreate(context.Background(), "alice-container", "alice")
	if err == nil {
		t.Fatal("PreCreate succeeded")
	}
	msg := err.Error()
	for _, want := range []string{"pool/containers/alice-container", "manually"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q, so an operator cannot act on it: %v", want, err)
		}
	}
}

// Encryption unconfigured must not fail a create — the flag defaults off and
// existing deployments keep working.
func TestPreCreate_NoOpWhenEncryptionIsNotConfigured(t *testing.T) {
	var h *encryptionHooks
	ref, err := h.PreCreate(context.Background(), "alice-container", "alice")
	if err != nil {
		t.Errorf("a nil hooks receiver failed the create: %v", err)
	}
	if ref.URI != "" || ref.Scheme != "" {
		t.Errorf("returned a key ref with no provider configured: %v", ref)
	}
}

func TestPreCreate_RequiresATenant(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}}

	if _, err := testHooksWith(t, z, p, refs).PreCreate(context.Background(), "orphan", ""); err == nil {
		t.Error("an empty tenant was accepted — Wrap would key the dataset under a tenant that " +
			"does not exist, and no later hook could resolve it")
	}
}
