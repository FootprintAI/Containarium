package sshconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrRefusedEmptyOverwrite is returned when a generation that produced no
// hosts would replace an existing, non-empty config.
//
// A zero-host generation is far more often an enumeration failure — an
// expired credential, a control plane that cannot see the caller's boxes,
// a partial outage — than a genuine "you have no containers". Writing it
// out destroys a file the operator may have accumulated over many syncs
// and cannot reconstruct without the very API that just came back empty.
// So the empty result is treated as suspect and the existing file is kept.
var ErrRefusedEmptyOverwrite = errors.New("refusing to overwrite a non-empty ssh config with a zero-host generation")

// WriteConfig writes a generated ssh config to path.
//
// It is the shared writer behind both `containarium ssh-config sync` and
// the sync_ssh_config MCP tool, so the safety rules below hold on every
// surface rather than on whichever one someone remembered to guard.
//
// Three properties:
//
//  1. A zero-host generation will not replace a non-empty existing file
//     unless force is true (see ErrRefusedEmptyOverwrite).
//  2. Any file being replaced is first copied to "<path>.bak", so even a
//     legitimate overwrite is recoverable.
//  3. The write is atomic: content lands in a temp file in the same
//     directory and is renamed over path, so an interrupted run cannot
//     leave a half-written config.
//
// Returns whether a backup was written.
func WriteConfig(path string, g Generated, force bool) (backedUp bool, err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Existing file is only interesting if it has content — replacing an
	// empty or absent file with an empty generation loses nothing.
	if g.Count == 0 && !force {
		if info, statErr := os.Stat(path); statErr == nil && info.Size() > 0 {
			return false, fmt.Errorf("%w: %s has content and this run generated 0 hosts "+
				"(usually an expired credential or a control plane that cannot see your boxes — "+
				"check `containarium whoami` before forcing)", ErrRefusedEmptyOverwrite, path)
		}
	}

	// Only worth backing up a file that has something in it — a .bak of an
	// empty file is noise the operator has to reason about later.
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > 0 {
		prev, readErr := os.ReadFile(path) // #nosec G304 G703 -- path is the caller's own --out/default config path, already stat'd above; reading it back to make a .bak is this function's job
		if readErr == nil {
			// Best-effort: a failed backup must not block the write, but a
			// successful one is reported so the caller can say where it went.
			if os.WriteFile(path+".bak", prev, 0o600) == nil {
				backedUp = true
			}
		}
	}

	tmp, err := os.CreateTemp(dir, ".ssh_config.*.tmp")
	if err != nil {
		return backedUp, fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once renamed

	// 0600 — the file lists every host the user can SSH to. Sensitive in
	// the same sense their ssh_config is.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return backedUp, fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.WriteString(g.Content); err != nil {
		_ = tmp.Close()
		return backedUp, fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return backedUp, fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return backedUp, fmt.Errorf("rename into %s: %w", path, err)
	}
	return backedUp, nil
}
