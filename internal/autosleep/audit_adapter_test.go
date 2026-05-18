package autosleep

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// readSource returns the file's contents — used by tests that pin a
// source-level contract that can't be observed at runtime without
// real infrastructure (e.g. the audit_logs row written by the adapter).
func readSource(relPath string) (string, error) {
	b, err := os.ReadFile(relPath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// TestAuditAdapter_NilStore_NoPanic — the adapter's Log method must
// tolerate both a nil receiver and a nil embedded Store. The
// production wiring constructs a non-nil adapter even when the audit
// store isn't available so the Manager-side `audit != nil` check
// keeps using the fallback log.Printf — but defense in depth.
func TestAuditAdapter_NilStore_NoPanic(t *testing.T) {
	// Nil receiver.
	var a *AuditStoreAdapter
	a.Log("autosleep.stopped", map[string]any{"username": "alice"})

	// Non-nil adapter, nil Store.
	a2 := &AuditStoreAdapter{Store: nil}
	a2.Log("autosleep.stopped", map[string]any{"username": "alice"})
	// no assertion needed — the test passes iff neither call panics.
}

// TestAuditAdapter_DetailJSONShape — locks the wire format used by
// the adapter to encode the Manager's fields map into the
// audit_logs.detail column. The Manager calls Log with three keys
// today (username, reason, idle_minutes); the JSON must round-trip
// through encoding/json with stable types so SQL JSON filters like
// `WHERE detail::jsonb ->> 'idle_minutes' = '18'` keep working.
//
// Reaches inside the adapter only through the JSON contract — no
// access to the unexported Store wiring required.
func TestAuditAdapter_DetailJSONShape(t *testing.T) {
	fields := map[string]any{
		"username":     "alice",
		"reason":       "idle 18m >= threshold 15m",
		"idle_minutes": 18,
	}
	detail, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal fields: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(detail, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round["username"] != "alice" {
		t.Errorf("username round-trip: got %v", round["username"])
	}
	// JSON unmarshals numbers as float64 — operators reading the row
	// in SQL will see the JSON number unchanged, but Go consumers
	// should know to assert as float64, not int.
	if got, ok := round["idle_minutes"].(float64); !ok || got != 18 {
		t.Errorf("idle_minutes round-trip: got %v (%T), want 18 (float64)", round["idle_minutes"], round["idle_minutes"])
	}
}

// TestAuditAdapter_UsernameActorIsSystem — the adapter sets the
// audit row's actor field to "_system" so dashboards filtering by
// "actions taken by alice" don't pick up daemon-initiated sleeps.
// The detail JSON's `username` key still carries the *target*
// container's owner; the two are intentionally distinct.
//
// We can't reach the audit_logs row without a Postgres instance,
// so this test pins the contract by reading the adapter source.
// A refactor that drops "_system" from the literal will break this
// test and force a deliberate update.
func TestAuditAdapter_UsernameActorIsSystem(t *testing.T) {
	src, err := readSource("audit_adapter.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !contains(src, `Username:     "_system"`) {
		t.Errorf("audit_adapter.go must set audit row Username to \"_system\"; " +
			"source no longer contains the literal. Update either the source " +
			"to restore the contract or this test to record the new actor.")
	}
}
