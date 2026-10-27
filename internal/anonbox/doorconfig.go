package anonbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// DefaultDoorStatePath is where the daemon persists the door's operator
// state so a kill switch or a ban survives a restart (#2200).
const DefaultDoorStatePath = "/var/lib/containarium/anon-door.json"

// DoorConfig is the operator-settable state of the door: open or closed
// (with the message a refused caller is told), and the banned keys. The
// per-box limits are daemon flags, not part of this file.
type DoorConfig struct {
	Enabled            bool     `json:"enabled"`
	DisabledMessage    string   `json:"disabled_message,omitempty"`
	BannedFingerprints []string `json:"banned_fingerprints,omitempty"`
}

// DefaultDoorConfig: open, nothing banned.
func DefaultDoorConfig() DoorConfig { return DoorConfig{Enabled: true} }

// DoorStore keeps DoorConfig in memory and on disk. Reads never touch the
// disk; writes go through atomically (temp file + rename). A file that
// exists but does not parse FAILS CLOSED: the door reports disabled with a
// message naming the problem, so a corrupt or hand-edited state file can
// never silently open the door.
type DoorStore struct {
	path string
	mu   sync.RWMutex
	cfg  DoorConfig
	err  error // non-nil = poisoned (malformed file); every Get reports closed
}

// NewDoorStore loads path. A missing file is the default (open) config;
// a malformed one poisons the store (see DoorStore). path "" keeps the
// store in memory only — fine for tests, wrong for a daemon.
func NewDoorStore(path string) *DoorStore {
	s := &DoorStore{path: path, cfg: DefaultDoorConfig()}
	if path == "" {
		return s
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the daemon's --anon-door-state flag (operator config), never caller input
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s
	case err != nil:
		s.err = fmt.Errorf("anonbox: read door state %s: %w", path, err)
		return s
	}
	var cfg DoorConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		s.err = fmt.Errorf("anonbox: door state %s is malformed: %w", path, err)
		return s
	}
	s.cfg = normalizeDoorConfig(cfg)
	return s
}

// Err reports whether the store is poisoned.
func (s *DoorStore) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}

// Get returns the effective config. A poisoned store reports closed with
// the poisoning error as the message.
func (s *DoorStore) Get() DoorConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.err != nil {
		return DoorConfig{Enabled: false, DisabledMessage: "anonymous door is closed: " + s.err.Error()}
	}
	return cloneDoorConfig(s.cfg)
}

// Set replaces the config and persists it. A successful Set also clears
// a poisoned state: the operator has written a known-good file.
func (s *DoorStore) Set(cfg DoorConfig) error {
	cfg = normalizeDoorConfig(cfg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path != "" {
		if err := writeFileAtomic(s.path, cfg); err != nil {
			return err
		}
	}
	s.cfg = cfg
	s.err = nil
	return nil
}

// IsBanned reports whether fp is on the ban list.
func (s *DoorStore) IsBanned(fp string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.cfg.BannedFingerprints {
		if b == fp {
			return true
		}
	}
	return false
}

func normalizeDoorConfig(cfg DoorConfig) DoorConfig {
	seen := map[string]bool{}
	var banned []string
	for _, fp := range cfg.BannedFingerprints {
		fp = strings.TrimSpace(fp)
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		banned = append(banned, fp)
	}
	sort.Strings(banned)
	cfg.BannedFingerprints = banned
	cfg.DisabledMessage = strings.TrimSpace(cfg.DisabledMessage)
	return cfg
}

func cloneDoorConfig(cfg DoorConfig) DoorConfig {
	out := cfg
	out.BannedFingerprints = append([]string(nil), cfg.BannedFingerprints...)
	return out
}

func writeFileAtomic(path string, cfg DoorConfig) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("anonbox: encode door state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("anonbox: door state dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("anonbox: write door state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("anonbox: commit door state: %w", err)
	}
	return nil
}
