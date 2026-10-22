package sshsession

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Recorder appends one session lifecycle Record to a durable sink.
type Recorder interface {
	Record(rec Record) error
}

// JSONLRecorder appends one JSON object per line — the stable,
// machine-readable sink containerium#1980 requires: every record has the
// same field names (see Record), so a consumer never needs a regex to
// parse one. Safe for concurrent use.
type JSONLRecorder struct {
	mu   sync.Mutex
	w    io.Writer
	file *os.File // non-nil only when this recorder opened its own file.
	path string   // the path file was opened at; empty for a writer-backed recorder.
}

// NewJSONLFileRecorder opens (creating if needed) path for append-only
// writes and returns a Recorder backed by it. The file is opened 0600:
// these records name a real client IP and a login/target pairing —
// operational metadata, not secret material (see Credential's doc
// comment), but still not meant to be world-readable.
func NewJSONLFileRecorder(path string) (*JSONLRecorder, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create session record sink directory %q: %w", dir, err)
		}
	}

	// #nosec G304 -- path is the operator's own --records-file flag on the
	// sentinel's ssh-session-plugin subcommand (see
	// internal/cmd/sentinel_ssh_session_plugin.go), not attacker-controlled
	// input. Choosing where the sink lands is the flag's entire purpose,
	// the same shape as internal/cmd/sentinel_pprof.go's --output path.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open session record sink %q: %w", path, err)
	}

	return &JSONLRecorder{w: f, file: f, path: path}, nil
}

// NewJSONLRecorder wraps an already-open writer (e.g. a bytes.Buffer in
// tests) instead of opening a file.
func NewJSONLRecorder(w io.Writer) *JSONLRecorder {
	return &JSONLRecorder{w: w}
}

// Record marshals rec as one JSON line and appends it.
func (j *JSONLRecorder) Record(rec Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal session record: %w", err)
	}
	line = append(line, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()

	if _, err := j.w.Write(line); err != nil {
		return fmt.Errorf("write session record: %w", err)
	}

	return nil
}

// Reopen closes the sink and opens the same PATH again (#2415). logrotate in
// create mode renames the sink and leaves a fresh file at the path; without a
// reopen the plugin keeps appending to the renamed file for as long as
// sshpiperd runs, so new sessions would land in a file about to be
// compressed and expired. Wired to SIGHUP by ReopenOn.
//
// The new file is opened BEFORE the old one is released: if it cannot be
// opened the recorder keeps its old handle and returns the error, because
// writing to the rotated file loses nothing and dropping records does.
// A writer-backed recorder (no path) has nothing to reopen.
func (j *JSONLRecorder) Reopen() error {
	if j.path == "" {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	// #nosec G304 -- same operator-supplied sink path NewJSONLFileRecorder opened.
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("reopen session record sink %q: %w", j.path, err)
	}
	old := j.file
	j.w, j.file = f, f
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Reopener is what ReopenOn drives.
type Reopener interface{ Reopen() error }

// ReopenOn calls r.Reopen once per value received on sigs until ctx is
// cancelled, logging (never failing on) an error: a plugin that exits
// because a rotation hiccuped would drop the live SSH proxy chain with it.
func ReopenOn(ctx context.Context, sigs <-chan os.Signal, r Reopener, logf func(format string, args ...any)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sigs:
			if err := r.Reopen(); err != nil {
				logf("ssh-session-plugin: SIGHUP reopen failed, still writing to the previous file: %v", err)
				continue
			}
			logf("ssh-session-plugin: reopened session record sink after SIGHUP")
		}
	}
}

// Close closes the underlying file, if this recorder opened one.
func (j *JSONLRecorder) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	return j.file.Close()
}
