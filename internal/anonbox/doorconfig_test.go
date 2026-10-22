package anonbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoorStore_MissingFileIsOpen(t *testing.T) {
	s := NewDoorStore(filepath.Join(t.TempDir(), "anon-door.json"))
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	if cfg := s.Get(); !cfg.Enabled || len(cfg.BannedFingerprints) != 0 {
		t.Errorf("default = %+v, want open and empty", cfg)
	}
}

func TestDoorStore_SetPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "anon-door.json")
	s := NewDoorStore(path)
	in := DoorConfig{Enabled: false, DisabledMessage: "  closed for maintenance ", BannedFingerprints: []string{"SHA256:b", " SHA256:a ", "SHA256:b", ""}}
	if err := s.Set(in); err != nil {
		t.Fatal(err)
	}
	want := DoorConfig{Enabled: false, DisabledMessage: "closed for maintenance", BannedFingerprints: []string{"SHA256:a", "SHA256:b"}}
	check := func(label string, cfg DoorConfig) {
		t.Helper()
		if cfg.Enabled != want.Enabled || cfg.DisabledMessage != want.DisabledMessage || strings.Join(cfg.BannedFingerprints, ",") != strings.Join(want.BannedFingerprints, ",") {
			t.Errorf("%s = %+v, want %+v", label, cfg, want)
		}
	}
	check("in-memory", s.Get())
	check("reloaded", NewDoorStore(path).Get())
	if !s.IsBanned("SHA256:a") || s.IsBanned("SHA256:c") {
		t.Errorf("IsBanned wrong")
	}
	// Get hands out a copy.
	got := s.Get()
	got.BannedFingerprints[0] = "mutated"
	if s.Get().BannedFingerprints[0] != "SHA256:a" {
		t.Errorf("Get must not alias internal state")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind")
	}
}

func TestDoorStore_MalformedFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anon-door.json")
	if err := os.WriteFile(path, []byte(`{"enabled": true,`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewDoorStore(path)
	if s.Err() == nil {
		t.Fatal("malformed file must poison the store")
	}
	cfg := s.Get()
	if cfg.Enabled || !strings.Contains(cfg.DisabledMessage, "malformed") {
		t.Errorf("poisoned store must report closed with the reason: %+v", cfg)
	}
	// A deliberate Set repairs it.
	if err := s.Set(DefaultDoorConfig()); err != nil {
		t.Fatal(err)
	}
	if s.Err() != nil || !s.Get().Enabled {
		t.Errorf("Set must clear the poison: err=%v cfg=%+v", s.Err(), s.Get())
	}
}

func TestDoorStore_InMemoryOnly(t *testing.T) {
	s := NewDoorStore("")
	if err := s.Set(DoorConfig{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if s.Get().Enabled {
		t.Error("in-memory set not applied")
	}
}
