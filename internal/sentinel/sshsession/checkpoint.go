package sshsession

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultCheckpointFile is where the shipper persists its progress.
const DefaultCheckpointFile = "/var/lib/containarium/ssh-session-shipper/checkpoint.json"

// Checkpoint is the shipper's durable progress marker over the JSONL sink.
//
// Progress is tracked per backend, because every record is shipped to the
// backend its login routes to, and one unreachable backend must not stall the
// others:
//
//   - Inode identifies the file the offsets refer to, so a rename-style
//     rotation is detected (a path alone cannot tell the rotated file from
//     its replacement).
//   - Base is a byte offset before which EVERY backend is fully caught up.
//     Each pass starts scanning at Base.
//   - Offsets holds, for a backend that is ahead of Base, the offset after
//     the last record confirmed shipped to it. A backend with no entry is
//     exactly at Base.
//
// An offset only ever moves after the backend answered OK for the batch it
// covers — the checkpoint rule that, together with the server's dedupe,
// gives at-least-once delivery with exactly-once rows.
type Checkpoint struct {
	Inode   uint64           `json:"inode"`
	Base    int64            `json:"base"`
	Offsets map[string]int64 `json:"offsets,omitempty"`
	// ExpiryWarned records, per backend, the unix time of the last
	// "token near expiry" warning, so it is logged once a day and not once
	// a pass — and survives a restart.
	ExpiryWarned map[string]int64 `json:"expiry_warned,omitempty"`
}

// offsetFor returns how far backend is confirmed shipped.
func (c *Checkpoint) offsetFor(backend string) int64 {
	if o, ok := c.Offsets[backend]; ok && o > c.Base {
		return o
	}
	return c.Base
}

// LoadCheckpoint reads path. A missing file is a fresh checkpoint (ship the
// whole sink); a corrupt one is an error — silently restarting from zero
// would re-ship everything, silently trusting garbage could skip records.
func LoadCheckpoint(path string) (*Checkpoint, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Checkpoint{}, nil
		}
		return nil, fmt.Errorf("read checkpoint %s: %w", path, err)
	}
	var c Checkpoint
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse checkpoint %s: %w", path, err)
	}
	return &c, nil
}

// SaveCheckpoint atomically writes c to path at mode 0600.
func SaveCheckpoint(path string, c *Checkpoint) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create checkpoint dir %s: %w", dir, err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".checkpoint-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp checkpoint: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp checkpoint: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp checkpoint: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp checkpoint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp checkpoint: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename checkpoint into place: %w", err)
	}
	return nil
}
