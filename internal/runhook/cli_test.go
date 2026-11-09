//go:build !windows

package runhook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The sink lives as long as its run: it stops once the run's exit sidecar is
// written, once the recorded process is gone, or when no run record shows up.
func TestRunEnded(t *testing.T) {
	since := time.Now().Add(-time.Minute)
	alive := func(int) bool { return true }
	dead := func(int) bool { return false }
	writeRecord := func(t *testing.T, dir string, started time.Time) {
		b, _ := json.Marshal(map[string]any{"pid": 42, "started_at": started})
		if err := os.WriteFile(filepath.Join(dir, "r1.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	if e, _ := runEnded(dir, "r1", since, time.Now(), alive); e {
		t.Error("no record yet, inside the grace period: still running")
	}
	if e, _ := runEnded(dir, "r1", since, since.Add(recordGrace+time.Second), alive); !e {
		t.Error("no record after the grace period: the run never started")
	}
	writeRecord(t, dir, time.Now())
	if e, _ := runEnded(dir, "r1", since, time.Now(), alive); e {
		t.Error("live process: still running")
	}
	if e, _ := runEnded(dir, "r1", since, time.Now(), dead); !e {
		t.Error("process gone: ended")
	}
	// A previous run's record and exit sidecar do not count.
	old := t.TempDir()
	writeRecord(t, old, since.Add(-time.Hour))
	if err := os.WriteFile(filepath.Join(old, "r1.exit"), []byte("0 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := since.Add(-time.Hour)
	_ = os.Chtimes(filepath.Join(old, "r1.exit"), past, past)
	if e, _ := runEnded(old, "r1", since, time.Now(), dead); e {
		t.Error("an earlier run's files must not stop this run's sink")
	}
	if err := os.WriteFile(filepath.Join(dir, "r1.exit"), []byte("0 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if e, _ := runEnded(dir, "r1", since, time.Now(), alive); !e {
		t.Error("exit sidecar written: ended")
	}
}

func TestRunHookCLI_ReadsConfigAndAnswers(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Socket = filepath.Join(dir, "missing.sock") // no sink: fail closed
	b, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	code := RunHookCLI([]string{"pre", "--config", path}, strings.NewReader(preInput("git status")), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("code=%d out=%s err=%s, want a deny when the sink is unreachable", code, out.String(), errb.String())
	}
	if code := RunHookCLI([]string{"bogus"}, strings.NewReader(""), &out, &errb); code == 0 {
		t.Error("an unknown hook must fail")
	}
}
