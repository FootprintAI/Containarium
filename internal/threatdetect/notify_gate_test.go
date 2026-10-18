package threatdetect

import (
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// gatedNotifier is a notifier with a controllable clock and no worker, so the
// queue length is the number of deliveries.
func gatedNotifier(interval time.Duration) (*WebhookNotifier, *time.Time) {
	n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil)
	n.SetRenotifyInterval(interval)
	clock := time.Unix(1_700_000_000, 0)
	n.gate.now = func() time.Time { return clock }
	return n, &clock
}

func openFinding(id int64, sev pb.ThreatSeverity) *Finding {
	f := testFinding(sev)
	f.ID = id
	return f
}

// #2643: a condition that stays true dedupes the row; the delivery must
// dedupe too, repeating only at the re-notify interval.
func TestWebhookNotifier_RepeatedUpsertsDeliverOncePerInterval(t *testing.T) {
	for _, tc := range []struct {
		name   string
		upsert int
		step   time.Duration
		want   int
	}{
		{"10 upserts in 10 minutes", 10, time.Minute, 1},
		{"10 upserts over 3 hours", 10, 18 * time.Minute, 3},
		{"every upsert past the interval", 4, 2 * time.Hour, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, clock := gatedNotifier(time.Hour)
			for i := 0; i < tc.upsert; i++ {
				f := openFinding(7, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM)
				f.Count = int64(i + 1)
				n.Notify(f)
				*clock = clock.Add(tc.step)
			}
			if got := len(n.queue); got != tc.want {
				t.Errorf("deliveries = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWebhookNotifier_Gate(t *testing.T) {
	t.Run("severity escalation delivers immediately", func(t *testing.T) {
		n, _ := gatedNotifier(time.Hour)
		n.Notify(openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
		n.Notify(openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
		n.Notify(openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_HIGH))
		n.Notify(openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM)) // de-escalation is not news
		if got := len(n.queue); got != 2 {
			t.Errorf("deliveries = %d, want 2", got)
		}
	})
	t.Run("distinct findings do not suppress each other", func(t *testing.T) {
		n, _ := gatedNotifier(time.Hour)
		for id := int64(1); id <= 3; id++ {
			n.Notify(openFinding(id, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
		}
		if got := len(n.queue); got != 3 {
			t.Errorf("deliveries = %d, want 3", got)
		}
	})
	t.Run("resolve delivers once and forgets the finding", func(t *testing.T) {
		n, _ := gatedNotifier(time.Hour)
		n.Notify(openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
		res := openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM)
		res.State = FindingStateResolved
		n.Notify(res)
		if got := len(n.queue); got != 2 {
			t.Fatalf("deliveries = %d, want open + resolved", got)
		}
		if len(n.gate.last) != 0 {
			t.Errorf("gate still tracks a resolved finding: %v", n.gate.last)
		}
	})
	t.Run("a finding with no id is never suppressed", func(t *testing.T) {
		n, _ := gatedNotifier(time.Hour)
		for i := 0; i < 3; i++ {
			n.Notify(openFinding(0, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
		}
		if got := len(n.queue); got != 3 {
			t.Errorf("deliveries = %d, want 3", got)
		}
	})
	t.Run("a dropped delivery does not suppress the retry", func(t *testing.T) {
		n, _ := gatedNotifier(time.Hour)
		n.queue = make(chan *Finding) // unbuffered, no reader: always full
		n.Notify(openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
		n.queue = make(chan *Finding, 1)
		n.Notify(openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
		if got := len(n.queue); got != 1 {
			t.Errorf("deliveries = %d, want 1 (the retry after a drop)", got)
		}
	})
	t.Run("memory is bounded", func(t *testing.T) {
		n, clock := gatedNotifier(time.Hour)
		n.queue = make(chan *Finding, gateMaxEntries+10)
		for id := int64(1); id <= gateMaxEntries+10; id++ {
			n.Notify(openFinding(id, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM))
			*clock = clock.Add(time.Second)
		}
		if got := len(n.gate.last); got > gateMaxEntries {
			t.Errorf("gate tracks %d findings, cap %d", got, gateMaxEntries)
		}
	})
	t.Run("non-positive interval means the default", func(t *testing.T) {
		n, _ := gatedNotifier(0)
		if n.gate.interval != DefaultRenotifyInterval {
			t.Errorf("interval = %s, want %s", n.gate.interval, DefaultRenotifyInterval)
		}
	})
}
