package sentinel

import (
	"path/filepath"
	"sort"
	"testing"
)

// #2415 — wiring the SSH session shipper into the sentinel process.

func TestFileAuditIngestTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	src := FileAuditIngestTokens{Path: path}

	if bs, err := src.Backends(); err != nil || len(bs) != 0 {
		t.Fatalf("no file: backends=%v err=%v", bs, err)
	}
	if _, ok, err := src.TokenFor("b1"); ok || err != nil {
		t.Fatalf("no file: ok=%v err=%v", ok, err)
	}

	if err := SaveAuditIngestTokenStore(path, []AuditIngestTokenEntry{{BackendID: "b1", Token: "t1"}, {BackendID: "b2", Token: "t2"}}); err != nil {
		t.Fatal(err)
	}
	if tok, ok, err := src.TokenFor("b2"); !ok || err != nil || tok != "t2" {
		t.Fatalf("TokenFor(b2) = %q,%v,%v", tok, ok, err)
	}
	if _, ok, _ := src.TokenFor("absent"); ok {
		t.Fatal("absent backend must report !ok")
	}
	bs, _ := src.Backends()
	sort.Strings(bs)
	if len(bs) != 2 || bs[0] != "b1" || bs[1] != "b2" {
		t.Fatalf("Backends = %v", bs)
	}

	// Re-read on every call: a rotation takes effect without a restart.
	_ = SaveAuditIngestTokenStore(path, []AuditIngestTokenEntry{{BackendID: "b2", Token: "t2-rotated"}})
	if tok, _, _ := src.TokenFor("b2"); tok != "t2-rotated" {
		t.Fatalf("rotated token not picked up: %q", tok)
	}
}

func TestManager_ShipperBackendURL(t *testing.T) {
	m := &Manager{backends: NewBackendPool(), config: Config{HealthPort: 8080}}
	m.backends.Add(&Backend{ID: "b1", IP: "10.0.0.7"})

	if got, err := m.shipperBackendURL("b1"); err != nil || got != "http://10.0.0.7:8080" {
		t.Fatalf("url = %q, %v", got, err)
	}
	if _, err := m.shipperBackendURL("gone"); err == nil {
		t.Fatal("a backend not in the pool must be an error (retried next pass)")
	}
}
