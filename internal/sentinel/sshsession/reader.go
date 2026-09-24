package sshsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// DefaultRecordsFile is the sink path used when nothing more specific is
// configured — the same default `containarium sentinel ssh-session-plugin`
// (see internal/cmd/sentinel_ssh_session_plugin.go) and `containarium
// sentinel ssh-sessions list`/`follow` (containarium#2004) fall back to, so
// there is exactly one place a change to that default has to happen.
const DefaultRecordsFile = "/var/log/containarium/ssh-sessions.jsonl"

// Filter narrows which records ReadRecords/Follow return. A zero Filter
// matches every record — an empty field is "don't filter on this", not
// "match empty".
type Filter struct {
	SessionID string
	Login     string
}

func (f Filter) matches(rec Record) bool {
	if f.SessionID != "" && rec.SessionID != f.SessionID {
		return false
	}
	if f.Login != "" && rec.Login != f.Login {
		return false
	}
	return true
}

// ReadRecords decodes every JSON-line record from r matching filter, in the
// order they appear in the stream — the order JSONLRecorder.Record appends
// them in, i.e. oldest first. Callers wanting newest-first (the `list`
// subcommand's default per containarium#2004) reverse the result
// themselves; Follow's own "as it happens" order is naturally
// chronological, so this function never reorders.
//
// A blank line is skipped rather than treated as an error — harmless
// against a sink whose last line ends in a trailing newline. A line that
// IS non-blank but fails to parse as a Record is an error: it means the
// sink is not what this reader expects, which is worth surfacing rather
// than silently dropping.
func ReadRecords(r io.Reader, filter Filter) ([]Record, error) {
	var out []Record
	scanner := bufio.NewScanner(r)
	// A session record is small, but don't let bufio.Scanner's 64KiB
	// default cap silently truncate a pathological line.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(text), &rec); err != nil {
			return out, fmt.Errorf("parse record at line %d: %w", lineNum, err)
		}
		if filter.matches(rec) {
			out = append(out, rec)
		}
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("read records: %w", err)
	}
	return out, nil
}

// ReadRecordsFile opens path and reads every matching record via
// ReadRecords. A missing file is reported as zero records, not an error:
// running `ssh-sessions list` before the plugin has ever written a session
// (or before it has been wired into sshpiperd's chain at all) is the
// expected first-run case, not a failure.
func ReadRecordsFile(path string, filter Filter) ([]Record, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied --records-file, see plugin.go's own justification.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return ReadRecords(f, filter)
}

// FollowPollInterval is how often Follow checks the sink file for new
// content and, before the file exists yet, for its creation. It is a
// package var rather than a const so tests can dial it down instead of
// sleeping through the production cadence — the same pattern
// internal/cmd/login.go uses for pollIntervalOverride.
var FollowPollInterval = 500 * time.Millisecond

// Follow tails path for records appended after Follow starts, sending
// each match on out as it is decoded, until ctx is cancelled (Follow then
// returns ctx.Err()). Like `tail -f` (not `tail -f -c +0`): it starts
// reading from the file's current end, so history is not replayed — a
// caller wanting both should call ReadRecordsFile first and then Follow.
//
// A path that does not exist yet is not an error: Follow waits for it to
// be created, matching `tail -f`'s own behavior against a not-yet-existing
// log file (e.g. before the ssh-session-plugin process has started).
//
// out must have spare capacity or an active reader: Follow blocks sending
// on it (respecting ctx cancellation), by design — silently dropping a
// session record because nobody was listening would defeat the point of
// an audit trail.
func Follow(ctx context.Context, path string, filter Filter, out chan<- Record) error {
	f, offset, err := openAtCurrentEnd(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var pending []byte
	chunk := make([]byte, 64*1024)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, readErr := f.ReadAt(chunk, offset)
		if n > 0 {
			offset += int64(n)
			pending = append(pending, chunk[:n]...)

			for {
				i := bytes.IndexByte(pending, '\n')
				if i < 0 {
					break
				}
				line := pending[:i]
				pending = pending[i+1:]

				text := strings.TrimSpace(string(line))
				if text == "" {
					continue
				}
				var rec Record
				if uerr := json.Unmarshal([]byte(text), &rec); uerr != nil {
					return fmt.Errorf("parse record: %w", uerr)
				}
				if !filter.matches(rec) {
					continue
				}
				select {
				case out <- rec:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			// Progress was made; go straight back to try reading more
			// rather than sleeping through a poll interval for no
			// reason.
			continue
		}

		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("read %q: %w", path, readErr)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(FollowPollInterval):
		}
	}
}

// openAtCurrentEnd opens path and returns it positioned to start reading
// "from now" — Follow's doc comment promise.
//
// What "now" means depends on whether the file already existed when Follow
// was asked to start:
//   - It already exists: skip its current content (that's history — a
//     caller wanting it calls ReadRecordsFile separately) and start at its
//     present end-of-file.
//   - It does not exist yet: there IS no history to skip, so once it's
//     created, start at offset 0. Anchoring to "current end" in this case
//     would race the very first write against Follow's own poll loop and
//     could silently skip it depending on exactly when the writer and the
//     poll happen to interleave.
func openAtCurrentEnd(ctx context.Context, path string) (*os.File, int64, error) {
	if info, err := os.Stat(path); err == nil {
		f, err := os.Open(path) // #nosec G304 -- operator-supplied --records-file, see plugin.go's own justification.
		if err != nil {
			return nil, 0, fmt.Errorf("open %q: %w", path, err)
		}
		return f, info.Size(), nil
	} else if !os.IsNotExist(err) {
		return nil, 0, fmt.Errorf("stat %q: %w", path, err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}

		f, err := os.Open(path) // #nosec G304 -- operator-supplied --records-file, see plugin.go's own justification.
		if err == nil {
			return f, 0, nil
		}
		if !os.IsNotExist(err) {
			return nil, 0, fmt.Errorf("open %q: %w", path, err)
		}

		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(FollowPollInterval):
		}
	}
}
