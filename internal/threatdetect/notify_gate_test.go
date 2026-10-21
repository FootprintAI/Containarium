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
			{"operator release resolves the finding in one write", resp(released, ReleasedByOperator), true, true},
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
				*clock = clock.Add(5 * time.Second) // inside the re-notify interval
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

// #2820: every resolve is delivered. The old release+resolve coalescing
// dropped a resolve landing within 30 s of an operator RELEASED delivery,
// which swallowed the resolve of a shared finding when box A's release (which
// kept it open) was followed by box B's release (which resolved it). An
// operator release that resolves is now one write, so nothing is dropped.
func TestWebhookNotifier_EveryResolveIsDelivered(t *testing.T) {
	released := func(state FindingState, box string) *Finding {
		f := openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		f.State = state
		f.Response = &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
			State: pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedBy: ReleasedByOperator, Container: box}
		return f
	}
	for _, tc := range []struct {
		name string
		box  string // the box the resolve's response names
	}{
		{"resolve a second after a release of the same box", "box-a"},
		{"resolve a second after a release of another box", "box-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, clock := gatedNotifier(time.Hour)
			n.Notify(released(FindingStateOpen, "box-a"))
			<-n.queue
			*clock = clock.Add(time.Second)
			n.Notify(released(FindingStateResolved, tc.box))
			if got := len(n.queue); got != 1 {
				t.Fatalf("resolve deliveries = %d, want 1", got)
			}
			if len(n.gate.last) != 0 {
				t.Errorf("gate still tracks a resolved finding: %v", n.gate.last)
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

// #2775: a kill is delivered. Under ALERT it leaves response.state at NONE, so
// the gate keys on the kill outcome (killed pid, skip reason kind) as well.
func TestWebhookNotifier_KillOutcomeIsDelivered(t *testing.T) {
	const (
		reused = pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED
		gone   = pb.KillSkipReason_KILL_SKIP_REASON_PROCESS_GONE
	)
	alert := func(k FindingResponse) *FindingResponse {
		k.Action, k.State = pb.ProcessAction_PROCESS_ACTION_ALERT, pb.ResponseState_RESPONSE_STATE_NONE
		return &k
	}
	throttle := func(state pb.ResponseState, by string, k FindingResponse) *FindingResponse {
		k.Action, k.State, k.ReleasedBy = pb.ProcessAction_PROCESS_ACTION_THROTTLE, state, by
		return &k
	}
	killed := func(pid, n uint32) FindingResponse {
		return FindingResponse{ProcessKilled: true, KilledPID: pid, Kills: n}
	}
	withSkip := func(k FindingResponse, skip pb.KillSkipReason) FindingResponse {
		k.KillSkipReason = skip
		return k
	}
	type step struct {
		name     string
		response *FindingResponse
		resolved bool
		after    time.Duration // clock advance after the step
		want     bool
		wantPID  uint32
		wantN    uint32
		wantSkip pb.KillSkipReason
	}
	const quick = 5 * time.Second
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"alert + kill: new finding, then killed", []step{
			{name: "upsert", want: true, after: quick},
			{name: "alert recorded, nothing killed", response: alert(FindingResponse{}), after: quick},
			{name: "kill recorded", response: alert(killed(4242, 1)), want: true, wantPID: 4242, wantN: 1, after: quick},
			{name: "repeat upsert", response: alert(killed(4242, 1))},
		}},
		{"throttle + kill: the APPLIED delivery carries the kill", []step{
			{name: "upsert", want: true, after: quick},
			{name: "applied with kill", response: throttle(pb.ResponseState_RESPONSE_STATE_APPLIED, "", killed(77, 1)), want: true, wantPID: 77, wantN: 1, after: quick},
			{name: "repeat upsert", response: throttle(pb.ResponseState_RESPONSE_STATE_APPLIED, "", killed(77, 1))},
		}},
		{"kill then an operator release that resolves: one post carrying the kill", []step{
			{name: "upsert", want: true, after: quick},
			{name: "kill recorded", response: alert(killed(4242, 1)), want: true, wantPID: 4242, wantN: 1, after: quick},
			{name: "release resolves in one write", response: throttle(pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedByOperator, killed(4242, 1)), resolved: true, want: true, wantPID: 4242, wantN: 1},
		}},
		{"skips are keyed on the reason kind, not text or pid", []step{
			{name: "upsert", want: true, after: quick},
			{name: "first skip is immediate", response: alert(FindingResponse{KillSkipReason: reused}), want: true, wantSkip: reused, after: quick},
			{name: "same kind again", response: alert(FindingResponse{KillSkipReason: reused}), after: quick},
			{name: "other kind inside the interval is held", response: alert(FindingResponse{KillSkipReason: gone}), after: KillRenotifyInterval},
			{name: "other kind after the interval", response: alert(FindingResponse{KillSkipReason: gone}), want: true, wantSkip: gone},
		}},
		{"a burst of kills: first at once, the rest once per interval with the latest pid and count", []step{
			{name: "upsert", want: true, after: quick},
			{name: "first kill", response: alert(killed(100, 1)), want: true, wantPID: 100, wantN: 1, after: quick},
			{name: "kill 2", response: alert(killed(101, 2)), after: quick},
			{name: "kill 3", response: alert(killed(102, 3)), after: quick},
			{name: "kill 4", response: alert(killed(103, 4)), after: KillRenotifyInterval},
			{name: "kill 5 after the interval carries the latest", response: alert(killed(104, 5)), want: true, wantPID: 104, wantN: 5, after: quick},
			{name: "kill 6", response: alert(killed(105, 6)), after: quick},
		}},
		{"shared finding: later kill held, the release post carries the latest and is not repeated", []step{
			{name: "upsert", want: true, after: quick},
			{name: "kill on box A", response: throttle(pb.ResponseState_RESPONSE_STATE_APPLIED, "", killed(11, 1)), want: true, wantPID: 11, wantN: 1, after: quick},
			{name: "kill on box B is held", response: throttle(pb.ResponseState_RESPONSE_STATE_APPLIED, "", killed(22, 2)), after: quick},
			{name: "release of A carries the current kill", response: throttle(pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedByOperator, killed(22, 2)), want: true, wantPID: 22, wantN: 2, after: quick},
			{name: "repeat of the release write", response: throttle(pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedByOperator, killed(22, 2))},
		}},
		{"first kill after a skip is immediate", []step{
			{name: "upsert", want: true, after: quick},
			{name: "skip", response: alert(FindingResponse{KillSkipReason: reused}), want: true, wantSkip: reused, after: quick},
			{name: "kill", response: alert(killed(9, 1)), want: true, wantPID: 9, wantN: 1},
		}},
		{"the first skip is immediate once, not after every delivered kill (review)", []step{
			{name: "upsert", want: true, after: quick},
			{name: "kill at t", response: alert(killed(1, 1)), want: true, wantPID: 1, wantN: 1, after: quick},
			{name: "skip at t+5s: the first skip", response: alert(withSkip(killed(1, 1), gone)), want: true, wantPID: 1, wantN: 1, wantSkip: gone, after: quick},
			{name: "kill at t+10s is held", response: alert(killed(2, 2)), after: 55 * time.Second},
			{name: "kill at t+65s, a minute after the last kill post", response: alert(killed(3, 3)), want: true, wantPID: 3, wantN: 3, after: quick},
			{name: "skip at t+70s is held: a skip was already delivered", response: alert(withSkip(killed(3, 3), gone))},
		}},
		{"no kill: alert-only adds no delivery", []step{
			{name: "upsert", want: true, after: quick},
			{name: "alert recorded", response: alert(FindingResponse{}), after: quick},
			{name: "repeat upsert", response: alert(FindingResponse{})},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, clock := gatedNotifier(24 * time.Hour)
			for _, s := range tc.steps {
				f := openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
				f.Response = s.response
				if s.resolved {
					f.State = FindingStateResolved
				}
				n.Notify(f)
				*clock = clock.Add(s.after)
				want := 0
				if s.want {
					want = 1
				}
				if got := len(n.queue); got != want {
					t.Fatalf("after %q: deliveries = %d, want %d", s.name, got, want)
				}
				if s.want {
					r := (<-n.queue).ToProto().GetResponse()
					if r.GetKilledPid() != s.wantPID || r.GetKills() != s.wantN || r.GetKillSkipReason() != s.wantSkip {
						t.Errorf("after %q: delivered killed_pid=%d kills=%d skip=%s, want %d %d %s", s.name, r.GetKilledPid(), r.GetKills(), r.GetKillSkipReason(), s.wantPID, s.wantN, s.wantSkip)
					}
				}
			}
		})
	}
}

// #2775: a respawning miner (one kill a second for an hour) is bounded by the
// kill interval, not one post per kill. #2816: so is one whose kill sometimes
// misses (the process exits first), at any skip spacing: the first kill and
// the first skip are immediate, then at most one post per
// KillRenotifyInterval. Measured: 60 or 61 posts an hour for every case below. With
// the "first skip" fast path re-armed after every delivered kill (the rule
// before skipSent) the skip-every-7s, -13s and -61s cases gave 116, 112 and
// 118, about two a minute.
func TestWebhookNotifier_RespawnStormIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		skipEvery int // every n-th exec's kill is skipped (PROCESS_GONE); 0 = never
	}{
		{"kills only", 0},
		{"a skip every 7s", 7},
		{"a skip every 13s", 13},
		{"a skip every 61s", 61},
		{"a skip every 2s", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, clock := gatedNotifier(24 * time.Hour)
			n.Notify(openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH))
			// The stored response as the responder's killFacts folds each
			// attempt into it: a kill bumps the count and clears the skip, a
			// skip keeps the last kill and records its reason.
			cur := FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE}
			for i := 1; i <= 3600; i++ {
				if tc.skipEvery > 0 && i%tc.skipEvery == 0 {
					cur.KillSkipReason = pb.KillSkipReason_KILL_SKIP_REASON_PROCESS_GONE
				} else {
					cur.ProcessKilled, cur.KilledPID, cur.Kills = true, uint32(1000+i), cur.Kills+1
					cur.KillSkipReason = pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED
				}
				f := openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
				r := cur
				f.Response = &r
				*clock = clock.Add(time.Second)
				n.Notify(f)
			}
			posts := len(n.queue) - 1 // the queue holds every accepted delivery (256 slots; a storm would overflow it), minus the new finding
			t.Logf("1 hour of execs at 1/s: %d posts", posts)
			perInterval := int(time.Hour / KillRenotifyInterval)
			if limit := 2 + perInterval; posts > limit {
				t.Fatalf("1 hour of kills at 1/s delivered %d posts, want at most %d (the first kill, the first skip, then one per %s)", posts, limit, KillRenotifyInterval)
			}
			if posts < perInterval-1 {
				t.Fatalf("1 hour of kills at 1/s delivered %d posts: the latest outcome should still get through about once per %s", posts, KillRenotifyInterval)
			}
		})
	}
}

// #2775 review: a miner that alternately dies and escapes the signal (a kill,
// then a PROCESS_GONE skip, every five seconds) is one post per interval in
// steady state, not two: the "first skip" fast path fires once per finding.
func TestWebhookNotifier_AlternatingKillAndSkipIsOnePostPerInterval(t *testing.T) {
	n, clock := gatedNotifier(24 * time.Hour)
	n.Notify(openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH))
	const runFor = 10 * time.Minute
	const step = 5 * time.Second
	kills := uint32(0)
	for elapsed := time.Duration(0); elapsed < runFor; elapsed += step {
		f := openFinding(9, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		r := &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE, ProcessKilled: kills > 0, KilledPID: 1000 + kills, Kills: kills}
		if (elapsed/step)%2 == 0 {
			kills++
			r.ProcessKilled, r.KilledPID, r.Kills = true, 1000+kills, kills
		} else {
			r.KillSkipReason = pb.KillSkipReason_KILL_SKIP_REASON_PROCESS_GONE
		}
		f.Response = r
		*clock = clock.Add(step)
		n.Notify(f)
	}
	posts := len(n.queue) - 1 // minus the new-finding delivery
	// The first kill and the first skip are immediate; after that at most one
	// changed outcome per KillRenotifyInterval.
	if limit := 2 + int(runFor/KillRenotifyInterval); posts > limit {
		t.Fatalf("%s of alternating kills and skips delivered %d posts, want at most %d (one per %s plus the first kill and the first skip)", runFor, posts, limit, KillRenotifyInterval)
	}
	if posts < 2+int(runFor/KillRenotifyInterval)-2 {
		t.Fatalf("%s of alternating kills and skips delivered %d posts: the re-notify interval should still let the latest outcome through about once a minute", runFor, posts)
	}
}

// #2775: the webhook body names the pid, the count and the skip reason as
// numbers/strings the consumer can read.
func TestFinding_WebhookPayloadNamesKilledPIDAndSkipReason(t *testing.T) {
	f := openFinding(1, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	f.Response = &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE,
		ProcessKilled: true, KilledPID: 4242, Kills: 3, KillSkipReason: pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED}
	body, err := json.Marshal(f.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Response struct {
			State          int32  `json:"state"`
			ProcessKilled  bool   `json:"process_killed"`
			KilledPID      uint32 `json:"killed_pid"`
			Kills          uint32 `json:"kills"`
			KillSkipReason int32  `json:"kill_skip_reason"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("payload %s: %v", body, err)
	}
	r := got.Response
	if r.KilledPID != 4242 || !r.ProcessKilled || r.Kills != 3 || r.KillSkipReason != int32(pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED) || r.State != 1 {
		t.Errorf("payload %s", body)
	}
}

// #2775: the response survives the JSONB column with its kill fields.
func TestFindingResponse_KillFieldsRoundTripStorage(t *testing.T) {
	in := FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE,
		ProcessKilled: true, KilledPID: 4242, Kills: 3, KillSkipReason: pb.KillSkipReason_KILL_SKIP_REASON_OTHER}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out FindingResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round trip: got %+v want %+v", out, in)
	}
}

// #2766 x #2775: a write from a box that killed nothing keeps the finding's
// kill whole (flag, latest pid, count), never killed with pid 0; a write that
// carries its own kill is left alone.
func TestFindingResponse_KeepKillOf(t *testing.T) {
	prev := &FindingResponse{ProcessKilled: true, KilledPID: 22, Kills: 2}
	r := FindingResponse{State: pb.ResponseState_RESPONSE_STATE_RELEASED}
	r.KeepKillOf(prev)
	if !r.ProcessKilled || r.KilledPID != 22 || r.Kills != 2 {
		t.Errorf("kept = %+v, want killed pid 22 kills 2", r)
	}
	own := FindingResponse{ProcessKilled: true, KilledPID: 30, Kills: 3}
	own.KeepKillOf(prev)
	if own.KilledPID != 30 || own.Kills != 3 {
		t.Errorf("own kill overwritten: %+v", own)
	}
	none := FindingResponse{}
	none.KeepKillOf(&FindingResponse{})
	none.KeepKillOf(nil)
	if none.ProcessKilled {
		t.Errorf("no kill on record invented one: %+v", none)
	}
}
