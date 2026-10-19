package threatdetect

import (
	"encoding/json"
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

// #2718: a response transition (applied, failed, released, expired) is news
// the operator must not have to poll for. It is delivered at once, inside the
// re-notify interval, the way a severity escalation is; an unchanged response
// is still a repeat. A release by an operator resolves the finding in the
// same call, and the pair is one delivery (the release), not two.
func TestWebhookNotifier_ResponseTransitions(t *testing.T) {
	resp := func(state pb.ResponseState, releasedBy string) *FindingResponse {
		return &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: state, ReleasedBy: releasedBy}
	}
	type step struct {
		name     string
		response *FindingResponse // nil = no response yet
		resolved bool
		want     bool // delivered?
	}
	var (
		none     = pb.ResponseState_RESPONSE_STATE_NONE
		applied  = pb.ResponseState_RESPONSE_STATE_APPLIED
		failed   = pb.ResponseState_RESPONSE_STATE_FAILED
		released = pb.ResponseState_RESPONSE_STATE_RELEASED
		expired  = pb.ResponseState_RESPONSE_STATE_EXPIRED
	)
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"applied then operator release and resolve", []step{
			{"upsert", nil, false, true},
			{"responder applies", resp(applied, ""), false, true},
			{"repeat upsert", resp(applied, ""), false, false},
			{"repeat upsert again", resp(applied, ""), false, false},
			{"operator releases", resp(released, ReleasedByOperator), false, true},
			{"release resolves the finding", resp(released, ReleasedByOperator), true, false},
		}},
		{"actuator error", []step{
			{"upsert", nil, false, true},
			{"responder fails", resp(failed, ReleasedByError), false, true},
			{"repeat upsert", resp(failed, ReleasedByError), false, false},
		}},
		{"ttl expiry", []step{
			{"upsert", nil, false, true},
			{"responder applies", resp(applied, ""), false, true},
			{"ttl releases", resp(expired, ReleasedByTTL), false, true},
			{"hand resolve later is still delivered", resp(expired, ReleasedByTTL), true, true},
		}},
		{"orphan-sweep release does not swallow a later resolve", []step{
			{"upsert", nil, false, true},
			{"sweep undoes a pending apply", resp(released, ReleasedByOrphanSweep), false, true},
			{"hand resolve", resp(released, ReleasedByOrphanSweep), true, true},
		}},
		{"alert-only response is not a transition", []step{
			{"upsert", nil, false, true},
			{"responder records alert-only", &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: none}, false, false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, clock := gatedNotifier(time.Hour)
			delivered := 0
			for _, s := range tc.steps {
				f := openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
				f.Response = s.response
				if s.resolved {
					f.State = FindingStateResolved
				}
				n.Notify(f)
				*clock = clock.Add(5 * time.Second) // inside the interval and the release+resolve window
				if s.want {
					delivered++
				}
				if got := len(n.queue); got != delivered {
					t.Fatalf("after %q: deliveries = %d, want %d", s.name, got, delivered)
				}
				if s.want {
					// drain and check the payload carries the response
					var last *Finding
					for len(n.queue) > 0 {
						last = <-n.queue
					}
					delivered = 0
					if s.response != nil && last.ToProto().GetResponse().GetState() != s.response.State {
						t.Errorf("after %q: delivered response = %s, want %s", s.name, last.ToProto().GetResponse().GetState(), s.response.State)
					}
				}
			}
			if s := tc.steps[len(tc.steps)-1]; s.resolved && len(n.gate.last) != 0 {
				t.Errorf("gate still tracks a resolved finding: %v", n.gate.last)
			}
		})
	}
}

// #2745 review: the release-then-resolve coalescing is bounded. A resolve is
// dropped only when it lands within releaseResolveWindow of the RELEASED
// delivery, and only once; if the resolve that release made failed, a later
// resolve is delivered.
func TestWebhookNotifier_ReleaseResolveCoalescingIsBounded(t *testing.T) {
	released := func(state FindingState) *Finding {
		f := openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		f.State = state
		f.Response = &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
			State: pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedBy: ReleasedByOperator}
		return f
	}
	for _, tc := range []struct {
		name  string
		gap   time.Duration // release delivery → resolve
		want  int           // deliveries for the resolve(s)
		twice bool          // a second resolve right after the first
	}{
		{"resolve right after the release is coalesced", time.Second, 0, false},
		{"failed resolve, resolve again 1 min later is delivered", time.Minute, 1, false},
		{"just past the window is delivered", releaseResolveWindow, 1, false},
		{"coalesced only once", time.Second, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, clock := gatedNotifier(time.Hour)
			n.Notify(released(FindingStateOpen))
			<-n.queue
			*clock = clock.Add(tc.gap)
			n.Notify(released(FindingStateResolved))
			if tc.twice {
				n.Notify(released(FindingStateResolved))
			}
			if got := len(n.queue); got != tc.want {
				t.Errorf("resolve deliveries = %d, want %d", got, tc.want)
			}
		})
	}
}

// #2718: the webhook payload is encoding/json over the proto, so enums go
// out as numbers, as severity always has; response.state follows that.
func TestFinding_WebhookPayloadEncodesResponseStateAsNumber(t *testing.T) {
	f := openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	f.Response = &FindingResponse{State: pb.ResponseState_RESPONSE_STATE_APPLIED}
	body, err := json.Marshal(f.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Severity int32 `json:"severity"`
		Response struct {
			State int32 `json:"state"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("payload %s: %v", body, err)
	}
	if got.Severity != int32(pb.ThreatSeverity_THREAT_SEVERITY_HIGH) || got.Response.State != int32(pb.ResponseState_RESPONSE_STATE_APPLIED) {
		t.Errorf("payload %s: want severity=%d response.state=%d", body, pb.ThreatSeverity_THREAT_SEVERITY_HIGH, pb.ResponseState_RESPONSE_STATE_APPLIED)
	}
}
