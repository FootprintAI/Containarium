package incus

import (
	"errors"
	"net/http"
	"testing"

	incusclient "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
)

// Storage-pool operations for per-tenant encrypted pools (#1338), per
// docs/architecture/per-tenant-encrypted-storage-pools.md.
//
// These pin the arguments that reach Incus and the shape of the answers
// coming back. They cannot pin whether a pool sourced at an encrypted dataset
// actually works — that is a property ZFS and Incus compute between them, and
// asserting it against a fake would assert the fake. The incus-tagged
// integration test is the authority for that.

// fakeStoragePoolServer implements only the storage-pool half of
// incus.InstanceServer.
//
// The embedded interface is nil on purpose: any method these tests do not
// stub panics with a nil-pointer dereference rather than silently returning a
// zero value. A test that starts exercising an unstubbed call should fail
// loudly, not pass on a zero.
type fakeStoragePoolServer struct {
	incusclient.InstanceServer

	pools map[string]*api.StoragePool

	created []api.StoragePoolsPost
	deleted []string

	createErr error
	getErr    error
	deleteErr error
}

func (f *fakeStoragePoolServer) CreateStoragePool(pool api.StoragePoolsPost) error {
	f.created = append(f.created, pool)
	return f.createErr
}

func (f *fakeStoragePoolServer) GetStoragePool(name string) (*api.StoragePool, string, error) {
	if f.getErr != nil {
		return nil, "", f.getErr
	}
	if p, ok := f.pools[name]; ok {
		return p, "", nil
	}
	return nil, "", notFoundErr()
}

func (f *fakeStoragePoolServer) DeleteStoragePool(name string) error {
	f.deleted = append(f.deleted, name)
	return f.deleteErr
}

// notFoundErr is the error Incus returns for a pool that does not exist.
// Built through the SDK's own status-error type so the production code is
// tested against the thing it will actually receive, not a string that
// happens to contain "not found".
func notFoundErr() error {
	return api.StatusErrorf(http.StatusNotFound, "Storage pool not found")
}

func TestCreateZFSPool_PassesTheSourceThrough(t *testing.T) {
	f := &fakeStoragePoolServer{}
	c := &Client{server: f}

	if err := c.CreateZFSPool("containarium-tenant-alice", "tank/tenants/alice"); err != nil {
		t.Fatalf("CreateZFSPool: %v", err)
	}

	if len(f.created) != 1 {
		t.Fatalf("CreateStoragePool called %d times, want 1", len(f.created))
	}
	got := f.created[0]
	if got.Name != "containarium-tenant-alice" {
		t.Errorf("pool name = %q, want %q", got.Name, "containarium-tenant-alice")
	}
	if got.Driver != string(StorageDriverZFS) {
		t.Errorf("driver = %q, want %q", got.Driver, StorageDriverZFS)
	}
	// The whole point of the call. A source that arrives altered — trimmed,
	// prefixed, lower-cased — puts the pool on a different dataset than the
	// one the caller encrypted, and every container on it would be
	// unencrypted while the daemon reported success.
	if got.Config["source"] != "tank/tenants/alice" {
		t.Errorf("source = %q, want %q — verbatim", got.Config["source"], "tank/tenants/alice")
	}
}

func TestCreateZFSPool_RejectsEmptyArguments(t *testing.T) {
	// An empty source is the dangerous one: Incus would create a pool on a
	// freshly-made loop device instead of the caller's encrypted dataset, and
	// it would succeed. Refuse before the API call rather than discover it
	// when a container turns out to be unencrypted.
	for _, tc := range []struct{ name, pool, source string }{
		{"no pool name", "", "tank/tenants/alice"},
		{"no source", "containarium-tenant-alice", ""},
		{"neither", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeStoragePoolServer{}
			c := &Client{server: f}
			if err := c.CreateZFSPool(tc.pool, tc.source); err == nil {
				t.Fatal("no error")
			}
			if len(f.created) != 0 {
				t.Errorf("Incus was called anyway: %+v", f.created)
			}
		})
	}
}

func TestCreateZFSPool_SurfacesTheIncusError(t *testing.T) {
	boom := errors.New("pool already exists")
	c := &Client{server: &fakeStoragePoolServer{createErr: boom}}

	err := c.CreateZFSPool("containarium-tenant-alice", "tank/tenants/alice")
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap %v — the hook decides rollback from this", err, boom)
	}
}

// StoragePoolSource must tell three states apart, and the middle one is why
// this function exists rather than callers using GetStoragePool directly:
//
//   - the pool is not there          → create it
//   - the pool is there, no source   → refuse; something else owns the name
//   - the pool is there with a source → reuse it if the source matches
//
// Collapsing "absent" into "exists with no source" makes a name collision
// look like an absent pool, and the hook would try to create over the top of
// whatever is already there.
func TestStoragePoolSource_ReportsAbsentDistinctlyFromEmpty(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pools      map[string]*api.StoragePool
		wantSource string
		wantExists bool
	}{
		{
			name: "pool with a source",
			pools: map[string]*api.StoragePool{
				"containarium-tenant-alice": {
					Name:           "containarium-tenant-alice",
					Driver:         "zfs",
					StoragePoolPut: api.StoragePoolPut{Config: map[string]string{"source": "tank/tenants/alice"}},
				},
			},
			wantSource: "tank/tenants/alice", wantExists: true,
		},
		{
			name: "pool with no source at all",
			pools: map[string]*api.StoragePool{
				"containarium-tenant-alice": {
					Name:           "containarium-tenant-alice",
					Driver:         "zfs",
					StoragePoolPut: api.StoragePoolPut{Config: map[string]string{}},
				},
			},
			wantSource: "", wantExists: true,
		},
		{
			name: "pool with a nil config map",
			pools: map[string]*api.StoragePool{
				"containarium-tenant-alice": {Name: "containarium-tenant-alice", Driver: "zfs"},
			},
			wantSource: "", wantExists: true,
		},
		{
			name:       "no such pool",
			pools:      map[string]*api.StoragePool{},
			wantSource: "", wantExists: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{server: &fakeStoragePoolServer{pools: tc.pools}}

			source, exists, err := c.StoragePoolSource("containarium-tenant-alice")
			if err != nil {
				t.Fatalf("StoragePoolSource: %v", err)
			}
			if exists != tc.wantExists {
				t.Errorf("exists = %v, want %v", exists, tc.wantExists)
			}
			if source != tc.wantSource {
				t.Errorf("source = %q, want %q", source, tc.wantSource)
			}
		})
	}
}

// A pool we could not read is not a pool that is absent. Reporting an
// unreadable pool as missing would have the hook create over the top of one
// that exists — the same "we could not check" vs "we checked and it is not
// there" distinction reviewExistingStorage already makes for the driver.
func TestStoragePoolSource_AnUnreadablePoolIsAnErrorNotAnAbsence(t *testing.T) {
	boom := errors.New("connection reset")
	c := &Client{server: &fakeStoragePoolServer{getErr: boom}}

	_, exists, err := c.StoragePoolSource("containarium-tenant-alice")
	if err == nil {
		t.Fatal("a pool that could not be read was reported as a clean answer")
	}
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap %v", err, boom)
	}
	if exists {
		t.Error("exists = true alongside an error — callers must not act on this")
	}
}

func TestDeleteStoragePool(t *testing.T) {
	f := &fakeStoragePoolServer{}
	c := &Client{server: f}

	if err := c.DeleteStoragePool("containarium-tenant-alice"); err != nil {
		t.Fatalf("DeleteStoragePool: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "containarium-tenant-alice" {
		t.Errorf("deleted = %v, want [containarium-tenant-alice]", f.deleted)
	}
}

// Deleting a pool that is already gone is the end state the caller wanted.
// Tenant offboarding (#1343) has to be re-runnable after a partial failure,
// and a hard error on the second run would leave the operator unable to
// finish a teardown they already started.
func TestDeleteStoragePool_AbsentIsNotAnError(t *testing.T) {
	c := &Client{server: &fakeStoragePoolServer{deleteErr: notFoundErr()}}

	if err := c.DeleteStoragePool("containarium-tenant-alice"); err != nil {
		t.Errorf("deleting an absent pool returned %v, want nil — teardown must be re-runnable", err)
	}
}

func TestDeleteStoragePool_SurfacesRealFailures(t *testing.T) {
	boom := errors.New("storage pool is in use")
	c := &Client{server: &fakeStoragePoolServer{deleteErr: boom}}

	if err := c.DeleteStoragePool("containarium-tenant-alice"); !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap %v — a pool still holding volumes must not "+
			"look like a successful teardown", err, boom)
	}
}

func TestDeleteStoragePool_RejectsAnEmptyName(t *testing.T) {
	f := &fakeStoragePoolServer{}
	c := &Client{server: f}

	if err := c.DeleteStoragePool(""); err == nil {
		t.Fatal("no error")
	}
	if len(f.deleted) != 0 {
		t.Errorf("Incus was called with an empty pool name: %v", f.deleted)
	}
}
