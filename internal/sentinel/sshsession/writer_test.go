package sshsession

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestJSONLRecorder_StableFieldNames guards acceptance criterion 6:
// records are machine-readable with stable field names, no regex needed.
// A plain map[string]interface{} decode must find every documented field
// under its exact JSON name.
func TestJSONLRecorder_StableFieldNames(t *testing.T) {
	var buf bytes.Buffer
	rec := Record{
		SessionID:  "sess-1",
		Phase:      SessionPhaseOpen,
		OccurredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ClientIP:   "203.0.113.7",
		ClientPort: 52341,
		Login:      "boxuser",
		Target:     "192.0.2.5:20022",
		AuthMethod: AuthMethodCertificate,
		Credential: Credential{
			KeyID:          "alice",
			Serial:         42,
			CAFingerprint:  "SHA256:ca",
			KeyFingerprint: "SHA256:key",
		},
	}

	w := NewJSONLRecorder(&buf)
	if err := w.Record(rec); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &decoded); err != nil {
		t.Fatalf("decode JSONL line: %v", err)
	}

	for _, field := range []string{
		"session_id", "phase", "occurred_at", "client_ip", "client_port",
		"login", "target", "auth_method", "key_id", "serial",
		"ca_key_fingerprint", "key_fingerprint",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing stable field %q in %v", field, decoded)
		}
	}

	if decoded["session_id"] != "sess-1" {
		t.Errorf("session_id = %v, want sess-1", decoded["session_id"])
	}
}

func TestJSONLRecorder_OneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONLRecorder(&buf)

	for i := 0; i < 3; i++ {
		if err := w.Record(Record{SessionID: "s", Phase: SessionPhaseOpen}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	scanner := bufio.NewScanner(&buf)
	lines := 0
	for scanner.Scan() {
		lines++
		var rec Record
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Errorf("line %d is not valid JSON on its own: %v", lines, err)
		}
	}
	if lines != 3 {
		t.Errorf("got %d lines, want 3", lines)
	}
}

func TestNewJSONLFileRecorder_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "does-not-exist-yet", "ssh-sessions.jsonl")

	w, err := NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatalf("NewJSONLFileRecorder: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.Record(Record{SessionID: "a", Phase: SessionPhaseOpen}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("sink file not created: %v", err)
	}
}

func TestNewJSONLFileRecorder_AppendsAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-sessions.jsonl")

	w1, err := NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatalf("NewJSONLFileRecorder: %v", err)
	}
	if err := w1.Record(Record{SessionID: "a", Phase: SessionPhaseOpen}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w2, err := NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatalf("reopen NewJSONLFileRecorder: %v", err)
	}
	if err := w2.Record(Record{SessionID: "a", Phase: SessionPhaseClose}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}

	lines := bytes.Count(bytes.TrimRight(data, "\n"), []byte("\n")) + 1
	if lines != 2 {
		t.Fatalf("got %d lines after reopen+append, want 2:\n%s", lines, data)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat sink: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("sink perm = %v, want 0600", fi.Mode().Perm())
	}
}
