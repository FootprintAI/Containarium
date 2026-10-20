package threatdetect

import (
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2820: a miner-signature finding shared by two boxes of one tenant. The
// gate sees what the stores hand it: for a response write, the finding
// carrying the record of the box the write is about (ResponseDelivery); for
// an upsert, the finding carrying whatever record it stores. Each box's apply
// and release is its own transition and is delivered, naming its box; an
// upsert repeating the stored record is not.
func TestWebhookNotifier_SharedFindingDeliversEachBox(t *testing.T) {
	var (
		applied  = pb.ResponseState_RESPONSE_STATE_APPLIED
		released = pb.ResponseState_RESPONSE_STATE_RELEASED
		expired  = pb.ResponseState_RESPONSE_STATE_EXPIRED
		failed   = pb.ResponseState_RESPONSE_STATE_FAILED
		none     = pb.ResponseState_RESPONSE_STATE_NONE
	)
	rec := func(box string, state pb.ResponseState, k ...uint32) *FindingResponse {
		r := &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: state, Container: box}
		if state == released {
			r.ReleasedBy = ReleasedByOperator
		}
		if len(k) == 2 {
			r.ProcessKilled, r.KilledPID, r.Kills = true, k[0], k[1]
		}
		return r
	}
	type step struct {
		name     string
		response *FindingResponse
		resolved bool
		after    time.Duration
		want     bool
		wantPID  uint32
	}
	const quick = 5 * time.Second
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"two boxes under THROTTLE: A applied, B applied, A released, B released and resolved", []step{
			{name: "new finding from box A", want: true, after: quick},
			{name: "A applied", response: rec("box-a", applied), want: true, after: quick},
			{name: "B's exec re-fires the finding (stored: A applied)", response: rec("box-a", applied), after: quick},
			{name: "B applied", response: rec("box-b", applied), want: true, after: quick},
			{name: "re-fire (stored: B applied)", response: rec("box-b", applied), after: quick},
			{name: "A released, B still holds (delivered: A's record)", response: rec("box-a", released), want: true, after: quick},
			{name: "re-fire (stored: still B applied)", response: rec("box-b", applied), after: quick},
			{name: "B released and resolved, 5 s after A's release", response: rec("box-b", released), resolved: true, want: true},
		}},
		{"released in the other order", []step{
			{name: "new", want: true, after: quick},
			{name: "A applied", response: rec("box-a", applied), want: true, after: quick},
			{name: "B applied", response: rec("box-b", applied), want: true, after: quick},
			{name: "B released, A still holds", response: rec("box-b", released), want: true, after: quick},
			{name: "re-fire (stored: A applied)", response: rec("box-a", applied), after: quick},
			{name: "A released and resolved", response: rec("box-a", released), resolved: true, want: true},
		}},
		{"expiry and failure on one box are delivered while the other holds", []step{
			{name: "new", want: true, after: quick},
			{name: "A applied", response: rec("box-a", applied), want: true, after: quick},
			{name: "B's apply fails", response: rec("box-b", failed), want: true, after: quick},
			{name: "A expires", response: rec("box-a", expired), want: true, after: quick},
		}},
		{"an alert-only box is not news", []step{
			{name: "new", want: true, after: quick},
			{name: "A applied", response: rec("box-a", applied), want: true, after: quick},
			{name: "box C alert-only", response: &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: none, Container: "box-c"}},
		}},
		{"kill + shared: B's apply carries the latest kill, a later kill is held, A's release carries it", []step{
			{name: "new", want: true, after: quick},
			{name: "A applied with a kill", response: rec("box-a", applied, 11, 1), want: true, wantPID: 11, after: quick},
			{name: "B applied with a kill", response: rec("box-b", applied, 22, 2), want: true, wantPID: 22, after: quick},
			{name: "another kill on B inside the interval is held", response: rec("box-b", applied, 33, 3), after: quick},
			{name: "A released carries the latest kill", response: rec("box-a", released, 33, 3), want: true, wantPID: 33, after: quick},
			{name: "re-fire (stored: B applied)", response: rec("box-b", applied, 33, 3), after: quick},
			{name: "B released and resolved", response: rec("box-b", released, 33, 3), resolved: true, want: true, wantPID: 33},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, clock := gatedNotifier(time.Hour)
			for _, s := range tc.steps {
				f := openFinding(6, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
				f.Response = s.response
				if s.response != nil {
					f.Container = s.response.Container // ResponseDelivery names the box
				}
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
				if !s.want {
					continue
				}
				got := (<-n.queue).ToProto()
				if s.response == nil {
					continue
				}
				r := got.GetResponse()
				if r.GetContainer() != s.response.Container || got.GetContainer() != s.response.Container || r.GetState() != s.response.State {
					t.Errorf("after %q: delivered %s on response.container=%q container=%q, want %s on %q",
						s.name, r.GetState(), r.GetContainer(), got.GetContainer(), s.response.State, s.response.Container)
				}
				if s.resolved && got.GetState() != pb.FindingState_FINDING_STATE_RESOLVED {
					t.Errorf("after %q: delivered finding state %s, want RESOLVED", s.name, got.GetState())
				}
				if r.GetKilledPid() != s.wantPID {
					t.Errorf("after %q: delivered killed_pid %d, want %d", s.name, r.GetKilledPid(), s.wantPID)
				}
			}
		})
	}
}

// #2820 x #2775: per-box response tracking must not reopen the respawn
// storm. Two boxes hold applied actions on one finding and a miner respawns
// once a second for an hour; the record the finding carries even flips
// between the two boxes on every write. Kills stay per finding, so it is
// still about one post a minute.
func TestWebhookNotifier_SharedFindingRespawnStormIsBounded(t *testing.T) {
	n, clock := gatedNotifier(24 * time.Hour)
	n.Notify(openFinding(6, pb.ThreatSeverity_THREAT_SEVERITY_HIGH))
	for _, box := range []string{"box-a", "box-b"} {
		f := openFinding(6, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		f.Response = &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: pb.ResponseState_RESPONSE_STATE_APPLIED, Container: box}
		n.Notify(f)
	}
	setup := len(n.queue)
	if setup != 3 {
		t.Fatalf("new + two applies delivered %d posts, want 3", setup)
	}
	for i := uint32(1); i <= 3600; i++ {
		f := openFinding(6, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		box := []string{"box-a", "box-b"}[i%2]
		f.Response = &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: pb.ResponseState_RESPONSE_STATE_APPLIED,
			Container: box, ProcessKilled: true, KilledPID: 1000 + i, Kills: i}
		*clock = clock.Add(time.Second)
		n.Notify(f)
	}
	posts := len(n.queue) - setup
	if limit := 1 + 3600/int(KillRenotifyInterval/time.Second) + 1; posts > limit {
		t.Fatalf("1 hour of kills at 1/s on a shared finding delivered %d posts, want at most %d", posts, limit)
	}
}

// #2820: ResponseDelivery names the write's box, carries its record and the
// kill on record, and is a copy of the stored finding.
func TestResponseDelivery_NamesTheBox(t *testing.T) {
	stored := openFinding(6, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	stored.Container = "box-a" // the box that first opened the shared finding
	stored.Response = &FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: pb.ResponseState_RESPONSE_STATE_APPLIED,
		Container: "box-b", ProcessKilled: true, KilledPID: 22, Kills: 2}
	box := FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: pb.ResponseState_RESPONSE_STATE_RELEASED,
		ReleasedBy: ReleasedByOperator, Container: "box-a"}
	got := ResponseDelivery(stored, box)
	if got.Container != "box-a" || got.Response.Container != "box-a" || got.Response.State != pb.ResponseState_RESPONSE_STATE_RELEASED {
		t.Fatalf("delivery = container %q response %+v, want box-a's RELEASED", got.Container, *got.Response)
	}
	if !got.Response.ProcessKilled || got.Response.KilledPID != 22 || got.Response.Kills != 2 {
		t.Errorf("delivery dropped the kill on record: %+v", *got.Response)
	}
	if stored.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED || stored.Response.Container != "box-b" || stored.Container != "box-a" {
		t.Errorf("ResponseDelivery changed the stored finding: container %q response %+v", stored.Container, *stored.Response)
	}
	legacy := ResponseDelivery(stored, FindingResponse{State: pb.ResponseState_RESPONSE_STATE_APPLIED})
	if legacy.Container != "box-a" {
		t.Errorf("a record naming no box renamed the finding to %q", legacy.Container)
	}
}

// #2820: the box rides the stored JSON and the wire form.
func TestFindingResponse_ContainerRoundTrips(t *testing.T) {
	in := FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_FREEZE, State: pb.ResponseState_RESPONSE_STATE_APPLIED, Container: "box-b"}
	raw, err := in.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var out FindingResponse
	if err := out.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	if out.Container != "box-b" {
		t.Errorf("stored container = %q after %s, want box-b", out.Container, raw)
	}
	if got := in.ToProto().GetContainer(); got != "box-b" {
		t.Errorf("wire container = %q, want box-b", got)
	}
	var old FindingResponse
	if err := old.UnmarshalJSON([]byte(`{"action":"PROCESS_ACTION_THROTTLE","state":"RESPONSE_STATE_APPLIED"}`)); err != nil || old.Container != "" {
		t.Errorf("a response stored before #2820 = %+v, %v; want it to decode with no box", old, err)
	}
}
