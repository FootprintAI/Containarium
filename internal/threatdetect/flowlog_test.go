package threatdetect

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
)

func flowLogFlow(src, dst string, dport uint16, bytes uint64) netbpf.FlowRecord {
	f := flow(src, dst)
	f.Dport = dport
	f.Bytes = bytes
	f.Packets = bytes / 100
	return f
}

var (
	flowLogT0      = time.Unix(1_700_000_000, 0)
	flowLogTenants = func(ip netip.Addr) (string, bool) {
		switch ip.String() {
		case "10.0.3.2", "10.0.3.3":
			return "org", true
		case "10.0.3.9":
			return "other", true
		}
		return "", false
	}
	flowLogBoxes = func(ip netip.Addr) (string, bool) {
		b := map[string]string{"10.0.3.2": "box-x", "10.0.3.3": "box-y", "10.0.3.9": "box-z"}[ip.String()]
		return b, b != ""
	}
)

func TestFlowLog_NilIsOff(t *testing.T) {
	var l *FlowLog
	l.Record(flowLogT0, []netbpf.FlowRecord{flowLogFlow("10.0.3.2", "93.184.1.1", 4444, 1)}, flowLogTenants, flowLogBoxes)
	if got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.1.1")}); got != nil {
		t.Fatalf("nil log returned %v", got)
	}
	if NewFlowLog(0, flowLogT0) != nil || NewFlowLog(-time.Hour, flowLogT0) != nil {
		t.Fatal("a non-positive retention must give a nil (off) log")
	}
	if l.Len() != 0 || l.Retention() != 0 {
		t.Fatal("nil log has no entries or retention")
	}
}

// The incident's question: which box contacted this destination and port?
func TestFlowLog_AttributesTheBox(t *testing.T) {
	l := NewFlowLog(2*time.Hour, flowLogT0)
	l.Record(flowLogT0, []netbpf.FlowRecord{
		flowLogFlow("10.0.3.2", "93.184.216.34", 4444, 5000),
		flowLogFlow("10.0.3.3", "93.184.1.1", 443, 100),
	}, flowLogTenants, flowLogBoxes)

	got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.216.34"), Dport: 4444})
	if len(got) != 1 || got[0].Container != "box-x" || got[0].TenantID != "org" || got[0].Src.String() != "10.0.3.2" {
		t.Fatalf("entries = %+v, want box-x of org", got)
	}
	if got[0].LikelyReply() {
		t.Error("a flow to port 4444 is box-initiated, not a likely reply")
	}
	// A different port, or a different destination, does not match.
	if got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.216.34"), Dport: 5555}); len(got) != 0 {
		t.Fatalf("wrong port matched: %+v", got)
	}
	if got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.216.35")}); len(got) != 0 {
		t.Fatalf("wrong destination matched: %+v", got)
	}
	// Port 0 matches any port.
	if got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.216.34")}); len(got) != 1 {
		t.Fatalf("any-port query = %+v", got)
	}
}

func TestFlowLog_OnlyPublicManagedSourcesRecorded(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	l.Record(flowLogT0, []netbpf.FlowRecord{
		flowLogFlow("10.0.3.2", "10.0.3.3", 22, 1),        // another box: private
		flowLogFlow("10.0.3.2", "100.64.1.1", 22, 1),      // CGNAT: reserved
		flowLogFlow("10.0.3.77", "93.184.1.1", 22, 1),     // source is not a managed box
		flowLogFlow("10.0.3.2", "169.254.169.254", 80, 1), // metadata
	}, flowLogTenants, flowLogBoxes)
	if n := l.Len(); n != 0 {
		t.Fatalf("log holds %d entries, want 0: only public destinations from managed boxes are kept", n)
	}
	// With no tenant resolver nothing can be attributed, so nothing is kept.
	l.Record(flowLogT0, []netbpf.FlowRecord{flowLogFlow("10.0.3.2", "93.184.1.1", 22, 1)}, nil, flowLogBoxes)
	if n := l.Len(); n != 0 {
		t.Fatalf("log holds %d entries without a tenant resolver", n)
	}
}

func TestFlowLog_FirstLastSeenAndCounters(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	rec := func(at time.Time, bytes uint64) {
		l.Record(at, []netbpf.FlowRecord{flowLogFlow("10.0.3.2", "93.184.1.1", 4444, bytes)}, flowLogTenants, flowLogBoxes)
	}
	rec(flowLogT0, 5000)
	rec(flowLogT0.Add(15*time.Second), 9000)
	rec(flowLogT0.Add(30*time.Second), 7000) // a smaller report must not lower the counter
	got, _ := l.Query(flowLogT0.Add(time.Minute), FlowLogQuery{Dst: netip.MustParseAddr("93.184.1.1")})
	if len(got) != 1 {
		t.Fatalf("entries = %+v, want one (same box, destination, port)", got)
	}
	e := got[0]
	if !e.FirstSeen.Equal(flowLogT0) || !e.LastSeen.Equal(flowLogT0.Add(30*time.Second)) {
		t.Errorf("first/last = %v / %v", e.FirstSeen, e.LastSeen)
	}
	if e.Bytes != 9000 {
		t.Errorf("bytes = %d, want the largest report, 9000", e.Bytes)
	}
}

// Two boxes (even of one org) contacting the same destination are two entries.
func TestFlowLog_BoxesStaySeparate(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	l.Record(flowLogT0, []netbpf.FlowRecord{
		flowLogFlow("10.0.3.2", "93.184.1.1", 4444, 1),
		flowLogFlow("10.0.3.3", "93.184.1.1", 4444, 1),
	}, flowLogTenants, flowLogBoxes)
	got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.1.1")})
	if len(got) != 2 || got[0].Container == got[1].Container {
		t.Fatalf("entries = %+v, want one per box", got)
	}
}

func TestFlowLog_TenantScopeAndLimit(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	for i, src := range []string{"10.0.3.2", "10.0.3.3", "10.0.3.9"} {
		l.Record(flowLogT0.Add(time.Duration(i)*time.Second), []netbpf.FlowRecord{flowLogFlow(src, "93.184.1.1", 4444, 1)}, flowLogTenants, flowLogBoxes)
	}
	dst := netip.MustParseAddr("93.184.1.1")
	if got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: dst, TenantID: "other"}); len(got) != 1 || got[0].Container != "box-z" {
		t.Fatalf("tenant filter = %+v, want only the other tenant's box", got)
	}
	got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: dst, Limit: 2})
	if len(got) != 2 || got[0].Container != "box-z" {
		t.Fatalf("limit 2 = %+v, want the two most recently seen, newest first", got)
	}
}

func TestFlowLog_TimeWindow(t *testing.T) {
	l := NewFlowLog(24*time.Hour, flowLogT0)
	dst := netip.MustParseAddr("93.184.1.1")
	l.Record(flowLogT0, []netbpf.FlowRecord{flowLogFlow("10.0.3.2", "93.184.1.1", 4444, 1)}, flowLogTenants, flowLogBoxes)
	l.Record(flowLogT0.Add(time.Hour), []netbpf.FlowRecord{flowLogFlow("10.0.3.3", "93.184.1.1", 4444, 1)}, flowLogTenants, flowLogBoxes)
	now := flowLogT0.Add(2 * time.Hour)

	// since: only entries last seen at or after it.
	if got, _ := l.Query(now, FlowLogQuery{Dst: dst, Since: flowLogT0.Add(30 * time.Minute)}); len(got) != 1 || got[0].Container != "box-y" {
		t.Fatalf("since = %+v, want box-y only", got)
	}
	// until: only entries first seen at or before it.
	if got, _ := l.Query(now, FlowLogQuery{Dst: dst, Until: flowLogT0.Add(30 * time.Minute)}); len(got) != 1 || got[0].Container != "box-x" {
		t.Fatalf("until = %+v, want box-x only", got)
	}
}

func TestFlowLog_RetentionPrunesAndCoverage(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	dst := netip.MustParseAddr("93.184.1.1")
	l.Record(flowLogT0, []netbpf.FlowRecord{flowLogFlow("10.0.3.2", "93.184.1.1", 4444, 1)}, flowLogTenants, flowLogBoxes)

	// Just started: coverage begins when recording did.
	if _, cs := l.Query(flowLogT0.Add(10*time.Minute), FlowLogQuery{Dst: dst}); !cs.Equal(flowLogT0) {
		t.Errorf("coveredSince = %v, want the recording start %v", cs, flowLogT0)
	}
	// Two hours on, a record of something else triggers the prune: the old
	// entry is gone and coverage slides to now - retention.
	later := flowLogT0.Add(2 * time.Hour)
	l.Record(later, []netbpf.FlowRecord{flowLogFlow("10.0.3.3", "93.184.9.9", 22, 1)}, flowLogTenants, flowLogBoxes)
	got, cs := l.Query(later, FlowLogQuery{Dst: dst})
	if len(got) != 0 {
		t.Fatalf("entries = %+v, want the expired one pruned", got)
	}
	if want := later.Add(-time.Hour); !cs.Equal(want) {
		t.Errorf("coveredSince = %v, want now-retention %v", cs, want)
	}
}

func TestFlowLog_RetentionClamped(t *testing.T) {
	if got := NewFlowLog(1000*time.Hour, flowLogT0).Retention(); got != MaxFlowLogRetention {
		t.Fatalf("retention = %v, want clamped to %v", got, MaxFlowLogRetention)
	}
}

func TestFlowLog_SizeBoundDropsOldest(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	l.maxEntries = 100
	for i := 0; i < 150; i++ {
		l.Record(flowLogT0.Add(time.Duration(i)*time.Second),
			[]netbpf.FlowRecord{flowLogFlow("10.0.3.2", fmt.Sprintf("93.184.%d.1", i), 22, 1)}, flowLogTenants, flowLogBoxes)
	}
	if n := l.Len(); n > 100 {
		t.Fatalf("log holds %d entries, want at most the bound of 100", n)
	}
	if got, _ := l.Query(flowLogT0.Add(time.Hour/2), FlowLogQuery{Dst: netip.MustParseAddr("93.184.149.1")}); len(got) != 1 {
		t.Fatal("the newest entry must survive eviction")
	}
	if got, _ := l.Query(flowLogT0.Add(time.Hour/2), FlowLogQuery{Dst: netip.MustParseAddr("93.184.0.1")}); len(got) != 0 {
		t.Fatal("the oldest entry must be the one evicted")
	}
}

// A box's reply to a client that connected to it targets the client's
// ephemeral port; the entry says so instead of claiming the box dialed out.
func TestFlowLog_LikelyReply(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	l.Record(flowLogT0, []netbpf.FlowRecord{flowLogFlow("10.0.3.2", "93.184.1.1", 51234, 1)}, flowLogTenants, flowLogBoxes)
	got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.1.1")})
	if len(got) != 1 || !got[0].LikelyReply() {
		t.Fatalf("entries = %+v, want one flagged as a likely reply", got)
	}
}

// A public-facing box answers many clients, each from a different ephemeral
// port. One entry per client address, not one per port: otherwise the log fills
// with visitors and retention collapses.
func TestFlowLog_RepliesCollapsePerClient(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	var flows []netbpf.FlowRecord
	for port := 40000; port < 40050; port++ {
		flows = append(flows, flowLogFlow("10.0.3.2", "93.184.1.1", uint16(port), 100))
	}
	l.Record(flowLogT0, flows, flowLogTenants, flowLogBoxes)
	if n := l.Len(); n != 1 {
		t.Fatalf("log holds %d entries for one client on 50 ports, want 1", n)
	}
	got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.1.1")})
	if len(got) != 1 || !got[0].LikelyReply() || got[0].Dport != 0 {
		t.Fatalf("entries = %+v, want one reply entry with no port", got)
	}
	// A reply entry never matches a port query: the port was the client's.
	if got, _ := l.Query(flowLogT0, FlowLogQuery{Dst: netip.MustParseAddr("93.184.1.1"), Dport: 40001}); len(got) != 0 {
		t.Fatalf("a port query matched a reply entry: %+v", got)
	}
}

// One box spraying destinations may use only its share of the log, and cannot
// wash another box's history out of it.
func TestFlowLog_PerSourceShare(t *testing.T) {
	l := NewFlowLog(time.Hour, flowLogT0)
	l.maxPerSource = 50
	l.Record(flowLogT0, []netbpf.FlowRecord{flowLogFlow("10.0.3.3", "93.184.216.34", 4444, 1)}, flowLogTenants, flowLogBoxes)
	for i := 0; i < 400; i++ {
		l.Record(flowLogT0.Add(time.Duration(i+1)*time.Second),
			[]netbpf.FlowRecord{flowLogFlow("10.0.3.2", fmt.Sprintf("93.184.%d.%d", i/250, 1+i%250), 22, 1)}, flowLogTenants, flowLogBoxes)
	}
	l.mu.Lock()
	sprayer, victim := l.perSource[netip.MustParseAddr("10.0.3.2")], l.perSource[netip.MustParseAddr("10.0.3.3")]
	l.mu.Unlock()
	if sprayer > 50 {
		t.Errorf("the spraying box holds %d entries, want at most its share of 50", sprayer)
	}
	if victim != 1 {
		t.Errorf("the other box holds %d entries, want its 1 untouched", victim)
	}
	if got, _ := l.Query(flowLogT0.Add(time.Hour/2), FlowLogQuery{Dst: netip.MustParseAddr("93.184.216.34")}); len(got) != 1 {
		t.Fatal("another box's history was washed out by a spraying box")
	}
	// The count and the map agree.
	total := 0
	l.mu.Lock()
	for _, n := range l.perSource {
		total += n
	}
	l.mu.Unlock()
	if total != l.Len() {
		t.Errorf("per-source counts sum to %d but the log holds %d entries", total, l.Len())
	}
}

// Coverage starts at the first poll, not at construction: until something has
// reported, the log can vouch for nothing.
func TestFlowLog_CoverageStartsAtTheFirstPoll(t *testing.T) {
	l := NewFlowLog(2*time.Hour, flowLogT0)
	dst := netip.MustParseAddr("93.184.1.1")
	if got, cs := l.Query(flowLogT0.Add(time.Hour), FlowLogQuery{Dst: dst}); got != nil || !cs.IsZero() {
		t.Fatalf("before any poll: entries=%v covered=%v, want no coverage at all", got, cs)
	}
	// An empty poll still means the log was listening from then on.
	l.Record(flowLogT0.Add(10*time.Minute), nil, flowLogTenants, flowLogBoxes)
	if _, cs := l.Query(flowLogT0.Add(time.Hour), FlowLogQuery{Dst: dst}); !cs.Equal(flowLogT0.Add(10 * time.Minute)) {
		t.Fatalf("covered = %v, want the first poll at T0+10m, not construction time", cs)
	}
}

// Entries dropped for size mean the log can no longer vouch for the time
// before them, even though the retention has not elapsed.
func TestFlowLog_CoverageMovesPastSizeEviction(t *testing.T) {
	l := NewFlowLog(24*time.Hour, flowLogT0)
	l.maxEntries = 100
	for i := 0; i < 150; i++ {
		l.Record(flowLogT0.Add(time.Duration(i)*time.Second),
			[]netbpf.FlowRecord{flowLogFlow("10.0.3.2", fmt.Sprintf("93.184.%d.1", i), 22, 1)}, flowLogTenants, flowLogBoxes)
	}
	_, cs := l.Query(flowLogT0.Add(time.Hour), FlowLogQuery{Dst: netip.MustParseAddr("93.184.149.1")})
	if !cs.After(flowLogT0) {
		t.Fatalf("covered = %v, want it moved past the start because older entries were evicted for size", cs)
	}
}
