package container

import (
	"errors"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// holdConfigBackend is a mock backend whose instance config is kept in a
// map, so Hold / Release can be read back.
func holdConfigBackend(cfg map[string]string) *incustest.MockBackend {
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: "Stopped"}
	mock.GetRawInstanceFunc = func(string) (map[string]string, string, error) {
		out := map[string]string{}
		for k, v := range cfg {
			out[k] = v
		}
		return out, "", nil
	}
	mock.SetConfigFunc = func(_, k, v string) error { cfg[k] = v; return nil }
	mock.UnsetConfigFunc = func(_, k string) error { delete(cfg, k); return nil }
	return mock
}

// A hold turns boot.autostart off, so a host or Incus restart leaves the box
// stopped, and a release puts the earlier value back (#3721).
func TestHoldRelease_AutostartOffWhileHeldAndRestored(t *testing.T) {
	cfg := map[string]string{incus.BootAutostartKey: "true"}
	m := NewWithBackend(holdConfigBackend(cfg))

	if err := m.Hold("alice"); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if cfg[incus.HoldKey] != "true" {
		t.Errorf("%s = %q, want true", incus.HoldKey, cfg[incus.HoldKey])
	}
	if cfg[incus.BootAutostartKey] != "false" {
		t.Errorf("held box: %s = %q, want false", incus.BootAutostartKey, cfg[incus.BootAutostartKey])
	}

	// A second hold must not record "false" as the value to restore.
	if err := m.Hold("alice"); err != nil {
		t.Fatalf("second Hold: %v", err)
	}

	if _, err := m.Release("alice"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, held := cfg[incus.HoldKey]; held {
		t.Errorf("released box still carries %s", incus.HoldKey)
	}
	if cfg[incus.BootAutostartKey] != "true" {
		t.Errorf("released box: %s = %q, want true (restored)", incus.BootAutostartKey, cfg[incus.BootAutostartKey])
	}
	if _, ok := cfg[incus.HoldPrevAutostartKey]; ok {
		t.Errorf("released box still carries %s", incus.HoldPrevAutostartKey)
	}
}

// A box that had no boot.autostart key of its own gets none back.
func TestHoldRelease_NoAutostartKeyBefore(t *testing.T) {
	cfg := map[string]string{}
	m := NewWithBackend(holdConfigBackend(cfg))

	if err := m.Hold("alice"); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if cfg[incus.BootAutostartKey] != "false" {
		t.Errorf("held box: %s = %q, want false", incus.BootAutostartKey, cfg[incus.BootAutostartKey])
	}
	if _, err := m.Release("alice"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if v, ok := cfg[incus.BootAutostartKey]; ok {
		t.Errorf("released box: %s = %q, want the key absent as before the hold", incus.BootAutostartKey, v)
	}
}

// A hold that cannot be stored is reported, never assumed.
func TestHold_WriteFailureIsReturned(t *testing.T) {
	mock := holdConfigBackend(map[string]string{})
	mock.SetConfigFunc = func(string, string, string) error { return errors.New("incus refused") }
	if err := NewWithBackend(mock).Hold("alice"); err == nil {
		t.Fatal("Hold returned nil although the config write failed")
	}
}

// Releasing a box that is not held changes nothing.
func TestRelease_NotHeldIsNoOp(t *testing.T) {
	cfg := map[string]string{incus.BootAutostartKey: "true"}
	mock := holdConfigBackend(cfg)
	writes := 0
	mock.SetConfigFunc = func(_, k, v string) error { writes++; cfg[k] = v; return nil }
	mock.UnsetConfigFunc = func(_, k string) error { writes++; delete(cfg, k); return nil }
	if released, err := NewWithBackend(mock).Release("alice"); err != nil || released {
		t.Fatalf("Release: %v", err)
	}
	if writes != 0 {
		t.Errorf("Release on an unheld box made %d config write(s), want 0", writes)
	}
}

// ReassertHolds, run at daemon start, turns boot.autostart off again on a
// held box where it drifted (a hold interrupted between its two writes), and
// leaves unheld boxes alone.
func TestReassertHolds_TurnsAutostartOffOnHeldBoxesOnly(t *testing.T) {
	cfgs := map[string]map[string]string{
		"alice-container": {incus.HoldKey: "true", incus.BootAutostartKey: "true"},
		"bob-container":   {incus.BootAutostartKey: "true"},
	}
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: "Stopped", Held: true}
	mock.Containers["bob-container"] = &incus.ContainerInfo{Name: "bob-container", State: "Stopped"}
	mock.GetRawInstanceFunc = func(n string) (map[string]string, string, error) { return cfgs[n], "", nil }
	mock.SetConfigFunc = func(n, k, v string) error { cfgs[n][k] = v; return nil }

	held, err := NewWithBackend(mock).ReassertHolds()
	if err != nil {
		t.Fatalf("ReassertHolds: %v", err)
	}
	if len(held) != 1 || held[0].Name != "alice-container" {
		t.Fatalf("held = %+v, want only alice-container", held)
	}
	if got := cfgs["alice-container"][incus.BootAutostartKey]; got != "false" {
		t.Errorf("held box: %s = %q, want false", incus.BootAutostartKey, got)
	}
	if got := cfgs["bob-container"][incus.BootAutostartKey]; got != "true" {
		t.Errorf("unheld box: %s = %q, want it left at true", incus.BootAutostartKey, got)
	}
}
