package transfer

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileEntry is one row in a manifest — a content hash and the file's mode.
// Size and mtime aren't recorded because they don't change the diff
// outcome (sha catches all content changes; mode catches the rest).
type fileEntry struct {
	Path string // relative to the manifest root, forward-slash-separated
	Hash string // hex-encoded sha256 of file content
	Mode uint32 // os.FileMode bits we care about: executable + special
}

// manifest is a sorted-by-path map of entries; comparison is straightforward.
type manifest struct {
	entries map[string]fileEntry
}

func newManifest() *manifest {
	return &manifest{entries: map[string]fileEntry{}}
}

// walkLocal builds a manifest for a local directory, skipping any path
// whose forward-slash form matches one of the excludes (substring match).
// Symlinks are NOT followed — they're skipped entirely in v1, since
// mirroring a symlink across the SSH boundary surprises in subtle ways.
//
// Uses os.Root (Go 1.24+) so every file open is kernel-enforced to stay
// inside the caller-specified root. This eliminates the symlink-TOCTOU
// traversal risk that gosec flags on plain filepath.Walk callbacks: even
// if a hostile directory swaps a regular file for a symlink between the
// walk's stat and our open, the open fails rather than escaping the root.
func walkLocal(rootDir string, excludes []string) (*manifest, error) {
	m := newManifest()

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("open root %s: %w", rootDir, err)
	}
	defer func() { _ = root.Close() }()

	err = fs.WalkDir(root.FS(), ".", func(relPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if relPath == "." {
			return nil
		}
		// Forward-slash form for cross-platform consistency.
		relSlash := filepath.ToSlash(relPath)

		if matchesAny(relSlash, excludes) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			// Skip symlinks, sockets, devices etc. They don't survive the
			// tar+ssh hop reliably.
			return nil
		}

		f, err := root.Open(relPath)
		if err != nil {
			return fmt.Errorf("open %s: %w", relPath, err)
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			return fmt.Errorf("hash %s: %w", relPath, err)
		}
		_ = f.Close()

		m.entries[relSlash] = fileEntry{
			Path: relSlash,
			Hash: hex.EncodeToString(h.Sum(nil)),
			Mode: uint32(info.Mode().Perm()),
		}
		return nil
	})

	return m, err
}

// matchesAny reports whether p matches any of the given substring patterns.
// Simple substring match (not glob) for v1 — keeps the implementation
// trivial. If/when patterns get complex, swap for filepath.Match.
func matchesAny(p string, patterns []string) bool {
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		if strings.Contains(p, pat) {
			return true
		}
	}
	return false
}

// parseRemoteManifest reads the line-oriented output of the remote
// manifest script:
//
//	<sha256> <mode-octal> <path>
//
// One line per file, paths forward-slash-separated, NUL-terminated paths
// are NOT used in v1 (so paths containing newlines aren't supported — fine
// for source trees).
func parseRemoteManifest(r io.Reader) (*manifest, error) {
	m := newManifest()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // accommodate long paths
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// hash (64) + space + mode (variable, octal) + space + path
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			continue // malformed — skip
		}
		hash := parts[0]
		modeStr := parts[1]
		path := parts[2]
		var mode uint32
		if _, err := fmt.Sscanf(modeStr, "%o", &mode); err != nil {
			mode = 0o644
		}
		m.entries[path] = fileEntry{Path: path, Hash: hash, Mode: mode}
	}
	return m, scanner.Err()
}

// diff computes the changes needed to make remote look like local.
type diffResult struct {
	ToAddOrModify []string // sorted, forward-slash paths
	ToDelete      []string // sorted, forward-slash paths (only acted on if Sync.Delete is true)
}

func (m *manifest) diff(remote *manifest) diffResult {
	var addMod, del []string
	for path, le := range m.entries {
		re, ok := remote.entries[path]
		if !ok || re.Hash != le.Hash || re.Mode != le.Mode {
			addMod = append(addMod, path)
		}
	}
	for path := range remote.entries {
		if _, ok := m.entries[path]; !ok {
			del = append(del, path)
		}
	}
	sort.Strings(addMod)
	sort.Strings(del)
	return diffResult{ToAddOrModify: addMod, ToDelete: del}
}
