package sshauthz

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SentinelKeyMarker is the comment line the daemon writes before the
// sentinel's upstream key in every jump account's authorized_keys
// (internal/gateway applySentinelKey). The key on the next non-empty line
// is the sentinel's, not a user's, and is never registered. A gateway test
// pins the two constants together.
const SentinelKeyMarker = "# sshpiper sentinel upstream key"

// BackfillStore is the one write the backfill needs.
type BackfillStore interface {
	InsertIfAbsent(ctx context.Context, rec KeyRecord) (bool, error)
}

// ScanAuthorizedKeys reads homeRoot/*/.ssh/authorized_keys and returns one
// backfill record per user key, created at now. Comments, blank lines,
// unparseable lines and the sentinel's marked block are skipped.
func ScanAuthorizedKeys(homeRoot string, now time.Time) ([]KeyRecord, error) {
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", homeRoot, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var out []KeyRecord
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		// #nosec G304 -- entry.Name() comes from os.ReadDir (no separators)
		// joined with a fixed suffix.
		f, err := os.Open(filepath.Join(homeRoot, username, ".ssh", "authorized_keys"))
		if err != nil {
			continue // no authorized_keys for this account
		}
		skipNext := false
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if line == SentinelKeyMarker {
				skipNext = true
				continue
			}
			if skipNext {
				skipNext = false
				continue
			}
			if strings.HasPrefix(line, "#") {
				continue
			}
			rec, err := NewKeyRecord(line, username, SourceBackfill, now)
			if err != nil {
				continue
			}
			out = append(out, rec)
		}
		scanErr := sc.Err()
		_ = f.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read %s authorized_keys: %w", username, scanErr)
		}
	}
	return out, nil
}

// Backfill registers every key found under homeRoot that the registry has
// no row for, with created_at = now and source = backfill. It is idempotent:
// a second run inserts nothing, and it never touches an existing row, so it
// cannot re-activate a revoked key. It returns the number of rows added.
func Backfill(ctx context.Context, store BackfillStore, homeRoot string, now time.Time) (int, error) {
	recs, err := ScanAuthorizedKeys(homeRoot, now)
	if err != nil {
		return 0, err
	}
	added := 0
	for _, rec := range recs {
		ok, err := store.InsertIfAbsent(ctx, rec)
		if err != nil {
			return added, err
		}
		if ok {
			added++
		}
	}
	return added, nil
}
