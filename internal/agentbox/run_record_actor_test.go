package agentbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The upgrade hazard this guards: RunRecordVersion went 1 -> 2 for the actor
// fields (#1699). readRunRecord used to reject any version != current, so a
// naive bump would have made every in-flight run unreadable at upgrade time —
// including the "unknown"-outcome records that are the only evidence of runs
// that died unresolved.
func TestReadRunRecord_AcceptsV1AfterTheActorBump(t *testing.T) {
	dir := t.TempDir()
	old := processLogDir
	processLogDir = dir
	defer func() { processLogDir = old }()

	// A v1 record exactly as a pre-#1699 agent-box would have written it:
	// no actor, no delegation_chain.
	v1 := map[string]any{
		"version":      1,
		"name":         "legacy",
		"pid":          4242,
		"boot_id":      bootID,
		"command":      "sleep 100",
		"capture_mode": "combined",
		"log_path":     filepath.Join(dir, "legacy.log"),
		"started_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, _ := json.Marshal(v1)
	if err := os.WriteFile(filepath.Join(dir, "legacy.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	rec, found, err := readRunRecord("legacy")
	if err != nil {
		t.Fatalf("v1 record must still read after the bump: %v", err)
	}
	if !found {
		t.Fatal("v1 record not found")
	}
	if rec.PID != 4242 {
		t.Errorf("PID = %d, want 4242", rec.PID)
	}
	if rec.Actor != "" {
		t.Errorf("Actor = %q, want empty (v1 recorded nobody)", rec.Actor)
	}
}

func TestReadRunRecord_RejectsAFutureVersion(t *testing.T) {
	dir := t.TempDir()
	old := processLogDir
	processLogDir = dir
	defer func() { processLogDir = old }()

	future := map[string]any{"version": RunRecordVersion + 1, "name": "future"}
	data, _ := json.Marshal(future)
	if err := os.WriteFile(filepath.Join(dir, "future.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Forward-incompatibility is a real error: an older binary cannot know
	// what a newer shape means, and guessing is worse than refusing.
	if _, _, err := readRunRecord("future"); err == nil {
		t.Fatal("a newer-than-supported record must be rejected, not parsed")
	}
}

func TestRunRecord_ActorRoundTrips(t *testing.T) {
	dir := t.TempDir()
	rec := RunRecord{
		Version:         RunRecordVersion,
		Name:            "attributed",
		PID:             1,
		BootID:          bootID,
		Command:         "echo hi",
		CaptureMode:     CaptureCombined,
		LogPath:         filepath.Join(dir, "attributed.log"),
		StartedAt:       time.Now(),
		Actor:           "alice@example.com",
		DelegationChain: `{"sub":"agent-x","act":{"sub":"alice@example.com"}}`,
	}
	if err := writeRunRecordAt(dir, rec); err != nil {
		t.Fatal(err)
	}
	old := processLogDir
	processLogDir = dir
	defer func() { processLogDir = old }()

	got, found, err := readRunRecord("attributed")
	if err != nil || !found {
		t.Fatalf("read back: %v found=%v", err, found)
	}
	if got.Actor != "alice@example.com" {
		t.Errorf("Actor = %q", got.Actor)
	}
	if got.DelegationChain != rec.DelegationChain {
		t.Errorf("DelegationChain = %q", got.DelegationChain)
	}
}

// An unattributed run must stay unattributed — never defaulted to the box
// user, which would fabricate attribution that nobody supplied.
func TestSpawn_EmptyActorStaysEmpty(t *testing.T) {
	dir := t.TempDir()
	old := processLogDir
	processLogDir = dir
	defer func() { processLogDir = old; waitForReapersForTest() }()

	mp, err := spawnBackgroundProcess("noactor", "true", "", CaptureCombined, "", "")
	if err != nil {
		t.Fatal(err)
	}
	rec, found, err := readRunRecord(mp.Name)
	if err != nil || !found {
		t.Fatalf("read: %v found=%v", err, found)
	}
	if rec.Actor != "" || rec.DelegationChain != "" {
		t.Errorf("actor fabricated: actor=%q chain=%q", rec.Actor, rec.DelegationChain)
	}
	if rec.Version != RunRecordVersion {
		t.Errorf("new records must be written at v%d, got v%d", RunRecordVersion, rec.Version)
	}
}
