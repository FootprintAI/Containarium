package incus

import (
	"strings"
	"testing"
)

// #1213: every root-disk construction hardcoded the pool literally named
// "default", so a backend migrated onto an isolated storage pool silently
// un-migrated itself — existing tenants stayed put while every NEW tenant
// landed back on the shared-filesystem pool. The contention probe went clean
// right after the migration and regressed weeks later as tenants arrived,
// with nothing in the product explaining why.

func TestStoragePool_DefaultsWhenUnset(t *testing.T) {
	t.Cleanup(func() { configuredStoragePool.Store("") })
	configuredStoragePool.Store("")

	c := &Client{}
	if got := c.StoragePool(); got != DefaultStoragePool {
		t.Errorf("StoragePool() = %q, want %q", got, DefaultStoragePool)
	}
}

// The process-wide setting is what reaches the clients built by subsystems
// that never see daemon config — the cloud actuator and several
// container_server helpers each call incus.New() for themselves. A
// per-client-only setting would be honoured on the daemon's client and
// ignored by all of those, which is the same silent divergence being fixed.
func TestStoragePool_ProcessWideSettingReachesFreshClients(t *testing.T) {
	t.Cleanup(func() { configuredStoragePool.Store("") })

	SetDefaultStoragePool("tenants")

	// A client built with no knowledge of the daemon's configuration.
	if got := (&Client{}).StoragePool(); got != "tenants" {
		t.Errorf("a freshly built client reports pool %q, want %q — it would create containers "+
			"on the pool the operator migrated away from (#1213)", got, "tenants")
	}
}

// A per-client override still wins, so a test (or a future per-placement
// caller) can target one pool without disturbing the process default.
func TestStoragePool_PerClientOverrideWins(t *testing.T) {
	t.Cleanup(func() { configuredStoragePool.Store("") })
	SetDefaultStoragePool("tenants")

	c := &Client{}
	c.SetStoragePool("scratch")
	if got := c.StoragePool(); got != "scratch" {
		t.Errorf("StoragePool() = %q, want the per-client override %q", got, "scratch")
	}
}

// Empty must not clobber a configured pool — otherwise a subsystem that
// calls the setter with an unset flag would quietly reset every later
// client back to "default".
func TestSetDefaultStoragePool_EmptyIsIgnored(t *testing.T) {
	t.Cleanup(func() { configuredStoragePool.Store("") })

	SetDefaultStoragePool("tenants")
	SetDefaultStoragePool("")

	if got := (&Client{}).StoragePool(); got != "tenants" {
		t.Errorf("an empty SetDefaultStoragePool reset the configured pool to %q", got)
	}
}

// #1213 AC3: changing the configured pool must REPOINT the default profile's
// root disk, not silently leave it.
//
// Setting the device only when absent is the other half of how a storage
// migration undoes itself: every container created without an explicit disk
// size inherits the default profile, so a stale root disk there sends them
// all back to the old pool no matter what the create path does.
func TestRootDiskForPool(t *testing.T) {
	t.Run("absent device is created", func(t *testing.T) {
		device, from, changed := rootDiskForPool(nil, "tenants")
		if !changed {
			t.Fatal("no device and no change reported")
		}
		if from != "" {
			t.Errorf("movedFrom = %q, want empty when there was no device", from)
		}
		if device["pool"] != "tenants" || device["path"] != "/" || device["type"] != "disk" {
			t.Errorf("device = %v", device)
		}
	})

	t.Run("stale pool is repointed", func(t *testing.T) {
		existing := map[string]string{"type": "disk", "path": "/", "pool": "default"}
		device, from, changed := rootDiskForPool(existing, "tenants")
		if !changed {
			t.Fatal("a root disk still naming the OLD pool was left alone; every container " +
				"inheriting the default profile would land back on it (#1213)")
		}
		if from != "default" {
			t.Errorf("movedFrom = %q, want %q so the move can be logged", from, "default")
		}
		if device["pool"] != "tenants" {
			t.Errorf("pool = %q, want %q", device["pool"], "tenants")
		}
	})

	t.Run("matching pool is left alone", func(t *testing.T) {
		existing := map[string]string{"type": "disk", "path": "/", "pool": "tenants"}
		if _, _, changed := rootDiskForPool(existing, "tenants"); changed {
			t.Error("an already-correct root disk was rewritten; that is a needless profile update " +
				"on every daemon start")
		}
	})

	// Only the pool is ours to change. An operator who set a size or IO limit
	// on the root device must not lose it to a repoint.
	t.Run("other device settings survive a repoint", func(t *testing.T) {
		existing := map[string]string{
			"type": "disk", "path": "/", "pool": "default",
			"size": "50GB", "limits.read": "100MB",
		}
		device, _, changed := rootDiskForPool(existing, "tenants")
		if !changed {
			t.Fatal("expected a repoint")
		}
		if device["size"] != "50GB" || device["limits.read"] != "100MB" {
			t.Errorf("operator settings lost in the repoint: %v", device)
		}
		// And the caller's map must not be mutated underneath them.
		if existing["pool"] != "default" {
			t.Errorf("the existing device map was mutated in place: %v", existing)
		}
	})
}

// buildContainerDataset is the daemon's understanding of where incus puts a
// container's ZFS dataset: a `containers` child of the pool's ROOT dataset,
// which is what the pool's `source` names.
//
// These cases previously asserted one segment too many, and were corrected in
// #1336 against a real pool. The rule is worth stating rather than pattern-
// matching, because the wrong version was derived by pattern-matching a real
// host's dataset name: on a daemon-provisioned pool the source already ends
// in `/containers`, so the right answer LOOKS doubled and the doubling got
// appended a second time. Only a real Incus can tell those two apart, so the
// authority for this layout is the incus-tagged integration test in
// pkg/core/box/lxc — these cases pin the arithmetic, not the truth.
func TestBuildContainerDataset(t *testing.T) {
	for _, tc := range []struct {
		name       string
		poolSource string
		poolName   string
		container  string
		want       string
	}{
		{
			// The normal case: the incus pool records the ZFS pool it sits on.
			name: "pool with an explicit source", poolSource: "tank", poolName: "default",
			container: "alice-container", want: "tank/containers/alice-container",
		},
		{
			// A pool created without an explicit source uses its own name.
			name: "pool without a source falls back to its name", poolSource: "", poolName: "default",
			container: "alice-container", want: "default/containers/alice-container",
		},
		{
			// A source that is itself a nested dataset is used verbatim.
			name: "nested source", poolSource: "tank/incus", poolName: "default",
			container: "bob", want: "tank/incus/containers/bob",
		},
		{
			// The shape EnsureStorage provisions, and the one that caused
			// #1336: the source already ends in /containers, so the correct
			// answer reads as doubled without the code doubling anything.
			name: "daemon-provisioned pool", poolSource: "incus-local/containers", poolName: "default",
			container: "alice-container", want: "incus-local/containers/containers/alice-container",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildContainerDataset(tc.poolSource, tc.poolName, tc.container); got != tc.want {
				t.Errorf("buildContainerDataset(%q, %q, %q) = %q, want %q",
					tc.poolSource, tc.poolName, tc.container, got, tc.want)
			}
		})
	}
}

// Exactly one `containers` segment is appended, whatever the source looks
// like. This replaces an assertion that required the segment to be DOUBLED —
// that test passed for four months and was wrong, because it asserted the
// implementation back to itself. Framed here as "append one, never two", so
// re-introducing the bug fails rather than looking like the layout.
func TestBuildContainerDataset_AppendsExactlyOneContainersSegment(t *testing.T) {
	got := buildContainerDataset("tank", "default", "alice")
	if strings.Contains(got, "/containers/containers/") {
		t.Errorf("dataset = %q — two `containers` segments were appended to a source that had "+
			"none. Incus puts an instance at <pool root>/containers/<name>; the extra level names "+
			"a dataset that does not exist (#1336)", got)
	}
	if want := "tank/containers/alice"; got != want {
		t.Errorf("dataset = %q, want %q", got, want)
	}
}
