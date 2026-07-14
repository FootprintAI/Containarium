package sentinel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultTunnelTokenStorePath is where dynamically-registered tunnel
// tokens (see TunnelTokenRegisterHandler) are persisted so a sentinel
// restart doesn't silently forget them (#936). TokenPolicy itself is a
// pure in-memory value with no memory across process restarts; a token
// registered via POST /sentinel/tunnel-tokens minutes or days before a
// restart would otherwise vanish, permanently locking out every host
// whose next handshake happens to land after that restart.
const DefaultTunnelTokenStorePath = "/etc/containarium/tunnel-tokens.json"

// TunnelTokenEntry is one persisted dynamic registration.
type TunnelTokenEntry struct {
	Token string `json:"token"`
	Pools []Pool `json:"pools"`
}

// LoadTunnelTokenStore reads previously-persisted dynamic registrations
// from path. A missing file is not an error — it means either a fresh
// sentinel or one that has never served a dynamic registration yet;
// callers get an empty slice and the sentinel starts with only its
// static CLI-flag tokens, exactly as it did before this store existed.
func LoadTunnelTokenStore(path string) ([]TunnelTokenEntry, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed, operator-controlled path (DefaultTunnelTokenStorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read tunnel token store %s: %w", path, err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	var entries []TunnelTokenEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("parse tunnel token store %s: %w", path, err)
	}
	return entries, nil
}

// ApplyTunnelTokenStore registers every persisted entry on policy. Called
// at sentinel startup, right after PolicyFromCLI builds the static
// policy, so a restart picks back up every token that was ever
// dynamically registered — not just the ones baked into --tunnel-token /
// --tunnel-token-policy.
func ApplyTunnelTokenStore(entries []TunnelTokenEntry, policy *TokenPolicy) {
	for _, e := range entries {
		policy.Allow(e.Token, e.Pools...)
	}
}

// SaveTunnelTokenStore atomically persists entries to path at mode 0600
// (each entry is a bearer-equivalent secret). Overwrites the whole file
// — the caller supplies the full current entry set, mirroring
// internal/cloud/config.go's Save().
func SaveTunnelTokenStore(path string, entries []TunnelTokenEntry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create tunnel token store dir %s: %w", dir, err)
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal tunnel token store: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tunnel-tokens-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp tunnel token store: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op if the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp tunnel token store: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp tunnel token store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp tunnel token store: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename tunnel token store into place: %w", err)
	}
	return nil
}

// upsertTunnelTokenEntry replaces entries[i] when its Token matches, or
// appends a new entry otherwise. Pure — used by the register handler to
// build the next full entry set before calling SaveTunnelTokenStore.
func upsertTunnelTokenEntry(entries []TunnelTokenEntry, token string, pools []Pool) []TunnelTokenEntry {
	for i := range entries {
		if entries[i].Token == token {
			entries[i].Pools = pools
			return entries
		}
	}
	return append(entries, TunnelTokenEntry{Token: token, Pools: pools})
}
