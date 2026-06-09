package reqrate

import (
	"strings"
	"testing"
	"time"
)

func TestCounter_SnapshotComputesRateAndResets(t *testing.T) {
	c := NewCounter()
	for i := 0; i < 6; i++ {
		c.Add("alice.example.com")
	}
	for i := 0; i < 3; i++ {
		c.Add("bob.example.com")
	}

	got := c.Snapshot(30 * time.Second)
	if got["alice.example.com"] != 0.2 { // 6 / 30s
		t.Errorf("alice rate = %v, want 0.2", got["alice.example.com"])
	}
	if got["bob.example.com"] != 0.1 { // 3 / 30s
		t.Errorf("bob rate = %v, want 0.1", got["bob.example.com"])
	}

	// Second snapshot of an untouched counter is empty — the window reset.
	if got := c.Snapshot(30 * time.Second); got != nil {
		t.Errorf("second snapshot = %v, want nil after reset", got)
	}
}

func TestCounter_SnapshotGuards(t *testing.T) {
	c := NewCounter()
	c.Add("x")
	if got := c.Snapshot(0); got != nil {
		t.Errorf("zero interval snapshot = %v, want nil", got)
	}
	// The guarded snapshot still reset the window, so a real one is now empty.
	if got := c.Snapshot(time.Second); got != nil {
		t.Errorf("snapshot after guarded reset = %v, want nil", got)
	}
}

func TestScan_CountsAccessRecordsSkipsJunk(t *testing.T) {
	log := strings.Join([]string{
		`{"msg":"handled request","request":{"host":"alice.example.com"}}`,
		`not json at all`,
		`{"msg":"handled request","request":{"host":"alice.example.com"}}`,
		`{"level":"info","msg":"serving initial configuration"}`, // no host
		`{"msg":"handled request","request":{"host":"bob.example.com:443"}}`,
		``, // blank line
	}, "\n")

	c := NewCounter()
	n, err := Scan(strings.NewReader(log), c)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 3 {
		t.Errorf("counted %d records, want 3", n)
	}
	got := c.Snapshot(time.Second)
	if got["alice.example.com"] != 2 {
		t.Errorf("alice count = %v, want 2", got["alice.example.com"])
	}
	if got["bob.example.com"] != 1 {
		t.Errorf("bob count = %v, want 1", got["bob.example.com"])
	}
}
