package sshauthz

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
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

// UnreadableAccount is an account whose authorized_keys the scan could not
// read as a plain file: a symlinked home, .ssh or authorized_keys, or an
// open or read error other than "does not exist". What keys it holds is
// unknown, so a caller must not treat it as holding none (#3241).
type UnreadableAccount struct {
	Username string
	Err      error
}

// ScanResult is what ScanAuthorizedKeys found. One bad account is reported in
// Unreadable and never fails the scan, so the other accounts stay usable.
type ScanResult struct {
	Records    []KeyRecord
	Unreadable []UnreadableAccount
}

// ScanAuthorizedKeys reads homeRoot/*/.ssh/authorized_keys and returns one
// backfill record per user key, created at now. Comments, blank lines,
// unparseable lines and the sentinel's marked block are skipped. An account
// with no authorized_keys holds nothing; an account whose home, .ssh or
// authorized_keys is a symlink, or cannot be opened or read, is listed in
// Unreadable and contributes no records. Only an unreadable homeRoot is an
// error.
func ScanAuthorizedKeys(homeRoot string, now time.Time) (ScanResult, error) {
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		return ScanResult{}, fmt.Errorf("read %s: %w", homeRoot, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var res ScanResult
	for _, entry := range entries {
		username := entry.Name()
		if entry.Type()&fs.ModeSymlink != 0 {
			res.Unreadable = append(res.Unreadable, UnreadableAccount{username, errSymlink})
			continue
		}
		if !entry.IsDir() {
			continue
		}
		recs, err := scanAccount(filepath.Join(homeRoot, username), username, now)
		if err != nil {
			res.Unreadable = append(res.Unreadable, UnreadableAccount{username, err})
			continue
		}
		res.Records = append(res.Records, recs...)
	}
	return res, nil
}

var errSymlink = errors.New("is a symlink")

// scanAccount reads one account's authorized_keys. A missing .ssh or file is
// no keys; a symlink on the way, or any other error, is returned.
func scanAccount(home, username string, now time.Time) ([]KeyRecord, error) {
	sshDir := filepath.Join(home, ".ssh")
	path := filepath.Join(sshDir, "authorized_keys")
	for _, p := range []string{sshDir, path} {
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // no authorized_keys for this account
		}
		if err != nil {
			return nil, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s %w", filepath.Base(p), errSymlink)
		}
	}
	// #nosec G304 -- username comes from os.ReadDir (no separators) joined
	// with a fixed suffix.
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []KeyRecord
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
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Backfill registers every key found under homeRoot that the registry has
// no row for (accounts it cannot read are logged and skipped), with created_at = now and source = backfill. It is idempotent:
// a second run inserts nothing, and it never touches an existing row, so it
// cannot re-activate a revoked key. It returns the number of rows added.
func Backfill(ctx context.Context, store BackfillStore, homeRoot string, now time.Time) (int, error) {
	res, err := ScanAuthorizedKeys(homeRoot, now)
	if err != nil {
		return 0, err
	}
	// An unreadable account is skipped, not fatal: one tenant's bad home must
	// not stop the registry for everyone. Its keys stay unregistered, so the
	// decider refuses them until the home is fixed and the daemon restarts.
	for _, u := range res.Unreadable {
		log.Printf("[ssh-keys] backfill skipped account %s: %v (#3241)", u.Username, u.Err)
	}
	added := 0
	for _, rec := range res.Records {
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
