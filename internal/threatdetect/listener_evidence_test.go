package threatdetect

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func listenerFinding(port uint32) *Finding {
	return &Finding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_BOX_ROGUE_SSH_LISTENER,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
		TenantID:  "alice",
		Container: "alice-container",
		Subject:   "alice-container",
		Evidence: Evidence{Listeners: []ListenerEvidence{
			{Port: port, BindAddress: "127.0.0.1", PID: 42, Binary: "/usr/sbin/dropbear", Note: "not the distro sshd binary"},
		}},
	}
}

func TestListenerEvidence_ToProto(t *testing.T) {
	p := listenerFinding(2222).ToProto()
	if len(p.Evidence.Listeners) != 1 {
		t.Fatalf("listeners = %d", len(p.Evidence.Listeners))
	}
	l := p.Evidence.Listeners[0]
	if l.Port != 2222 || l.BindAddress != "127.0.0.1" || l.Pid != 42 || l.Binary != "/usr/sbin/dropbear" || l.Note == "" {
		t.Errorf("proto listener = %+v", l)
	}
}

// The upsert paths (Postgres and in-memory) both append a re-fire's evidence
// with Evidence.merged; listeners must ride along or a second sighting on an
// open finding would silently drop its port.
func TestListenerEvidence_MergedKeepsBothSightings(t *testing.T) {
	a := listenerFinding(2222).Evidence
	b := listenerFinding(2200).Evidence
	got := a.merged(b)
	if len(got.Listeners) != 2 || got.Listeners[0].Port != 2222 || got.Listeners[1].Port != 2200 {
		t.Fatalf("merged listeners = %+v", got.Listeners)
	}
	if len(a.Listeners) != 1 {
		t.Error("merged must not mutate its receiver")
	}
}

func TestListenerEvidence_Capped(t *testing.T) {
	var ev Evidence
	for i := 0; i < EvidenceCap+5; i++ {
		ev.Listeners = append(ev.Listeners, ListenerEvidence{Port: uint32(1000 + i)})
	}
	got := ev.Capped()
	if len(got.Listeners) != EvidenceCap {
		t.Fatalf("len = %d, want %d", len(got.Listeners), EvidenceCap)
	}
	if got.Listeners[len(got.Listeners)-1].Port != uint32(1000+EvidenceCap+4) {
		t.Error("cap must keep the most recent entries")
	}
}
