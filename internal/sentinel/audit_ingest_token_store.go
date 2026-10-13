package sentinel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// #2415 — per-backend audit-ingest tokens.
//
// The sentinel's SSH session shipper authenticates to each backend's
// AuditService with a JWT that backend minted for it, scoped to audit:ingest
// only. Those tokens live here, keyed by backend id, in a file separate from
// the tunnel-join token store: the entries have a different shape and a
// different blast radius, and migrating a credential file's schema to share
// one would buy nothing.

// DefaultAuditIngestTokenStorePath is where registered tokens are persisted.
const DefaultAuditIngestTokenStorePath = "/etc/containarium/audit-ingest-tokens.json" // #nosec G101 -- a file PATH, not a credential

// AuditIngestTokenEntry is one backend's ingest token.
type AuditIngestTokenEntry struct {
	BackendID string `json:"backend_id"`
	Token     string `json:"token"`
}

// LoadAuditIngestTokenStore reads the persisted entries. A missing file is an
// empty store (nothing registered yet); a corrupt one is an error, never a
// silently empty set — that would look like "no token registered" and turn
// into skipped records.
func LoadAuditIngestTokenStore(path string) ([]AuditIngestTokenEntry, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed, operator-controlled path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read audit-ingest token store %s: %w", path, err)
	}
	var entries []AuditIngestTokenEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("parse audit-ingest token store %s: %w", path, err)
	}
	return entries, nil
}

// SaveAuditIngestTokenStore atomically persists the full entry set at mode
// 0600 (each token is a bearer credential for a backend's audit chain).
func SaveAuditIngestTokenStore(path string, entries []AuditIngestTokenEntry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit-ingest token store dir %s: %w", dir, err)
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal audit-ingest token store: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".audit-ingest-tokens-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp audit-ingest token store: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp audit-ingest token store: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp audit-ingest token store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp audit-ingest token store: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename audit-ingest token store into place: %w", err)
	}
	return nil
}

// upsertAuditIngestTokenEntry replaces backendID's token (a rotation) or
// appends a new entry.
func upsertAuditIngestTokenEntry(entries []AuditIngestTokenEntry, backendID, token string) []AuditIngestTokenEntry {
	for i := range entries {
		if entries[i].BackendID == backendID {
			entries[i].Token = token
			return entries
		}
	}
	return append(entries, AuditIngestTokenEntry{BackendID: backendID, Token: token})
}

// removeAuditIngestTokenEntry drops backendID's entry; absent is a no-op.
func removeAuditIngestTokenEntry(entries []AuditIngestTokenEntry, backendID string) []AuditIngestTokenEntry {
	out := entries[:0:0]
	for _, e := range entries {
		if e.BackendID != backendID {
			out = append(out, e)
		}
	}
	return out
}
