package threatdetect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// FindingResponse is stored as JSONB on security_findings; it must round-trip
// with enum names (not bare ints) so the column is readable in psql and
// stable if the enum grows.
func TestFindingResponse_JSONRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	in := FindingResponse{
		Action:     pb.ProcessAction_PROCESS_ACTION_THROTTLE,
		State:      pb.ResponseState_RESPONSE_STATE_APPLIED,
		AppliedAt:  t0,
		ExpiresAt:  t0.Add(24 * time.Hour),
		ReleasedBy: "",
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"PROCESS_ACTION_THROTTLE"`, `"RESPONSE_STATE_APPLIED"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON %s lacks %s", raw, want)
		}
	}
	var out FindingResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Action != in.Action || out.State != in.State || !out.AppliedAt.Equal(in.AppliedAt) || !out.ExpiresAt.Equal(in.ExpiresAt) || !out.ReleasedAt.IsZero() {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}

func TestFinding_ToProto_CarriesResponse(t *testing.T) {
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	f := &Finding{
		ID: 1, Rule: pb.ThreatRuleId(6), Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
		TenantID: "tenant-a", Container: "box-a", State: FindingStateOpen,
	}
	if f.ToProto().GetResponse() != nil {
		t.Fatal("ToProto() set a response on a finding that has none")
	}
	f.Response = &FindingResponse{
		Action: pb.ProcessAction_PROCESS_ACTION_FREEZE, State: pb.ResponseState_RESPONSE_STATE_FAILED,
		AppliedAt: t0, Error: "incus: frozen already",
	}
	got := f.ToProto().GetResponse()
	if got.GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE || got.GetState() != pb.ResponseState_RESPONSE_STATE_FAILED {
		t.Fatalf("response = %v, want FREEZE/FAILED", got)
	}
	if got.GetError() != "incus: frozen already" || !got.GetAppliedAt().AsTime().Equal(t0) || got.GetReleasedAt() != nil {
		t.Fatalf("response = %v: error/applied_at/released_at not carried", got)
	}
}
