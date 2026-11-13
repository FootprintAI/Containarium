package server

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// flowHistoryServer returns a server whose flow log holds: box-a (tenant
// alice) and box-b (tenant bob) both having dialed 93.184.216.34:4444.
func flowHistoryServer(t *testing.T) *ThreatDetectionServer {
	t.Helper()
	now := time.Now()
	fl := threatdetect.NewFlowLog(2*time.Hour, now.Add(-time.Hour))
	tenants := map[string]string{"10.0.3.2": "alice", "10.0.3.3": "bob"}
	boxes := map[string]string{"10.0.3.2": "box-a", "10.0.3.3": "box-b"}
	look := func(m map[string]string) func(netip.Addr) (string, bool) {
		return func(ip netip.Addr) (string, bool) { v, ok := m[ip.String()]; return v, ok }
	}
	pool := netip.MustParseAddr("93.184.216.34").As4()
	for _, src := range []string{"10.0.3.2", "10.0.3.3"} {
		s := netip.MustParseAddr(src).As4()
		rec := netbpf.FlowRecord{
			// The wire value is the 4 IPv4 bytes read back as a native uint32.
			Saddr: binary.NativeEndian.Uint32(s[:]),
			Daddr: binary.NativeEndian.Uint32(pool[:]),
			Sport: 40000, Dport: 4444, Proto: 6, Packets: 3, Bytes: 300,
		}
		fl.Record(now.Add(-30*time.Minute), []netbpf.FlowRecord{rec}, look(tenants), look(boxes))
	}
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFlowLog(fl)
	return s
}

func TestQueryFlowHistory_NotEnabled(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	_, err := s.QueryFlowHistory(ctx, &pb.QueryFlowHistoryRequest{DstIp: "93.184.216.34"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition: a disabled log must not read as an empty answer", status.Code(err))
	}
}

func TestQueryFlowHistory_Unauthenticated(t *testing.T) {
	s := flowHistoryServer(t)
	if _, err := s.QueryFlowHistory(context.Background(), &pb.QueryFlowHistoryRequest{DstIp: "93.184.216.34"}); err == nil {
		t.Fatal("a call with no authenticated subject must fail")
	}
}

func TestQueryFlowHistory_AdminSeesTheBoxes(t *testing.T) {
	s := flowHistoryServer(t)
	ctx := auth.ContextWithTestSubject(context.Background(), "root", auth.RoleAdmin)
	resp, err := s.QueryFlowHistory(ctx, &pb.QueryFlowHistoryRequest{DstIp: "93.184.216.34", DstPort: 4444})
	if err != nil {
		t.Fatalf("QueryFlowHistory: %v", err)
	}
	if len(resp.GetEntries()) != 2 {
		t.Fatalf("entries = %v, want both boxes", resp.GetEntries())
	}
	got := map[string]*pb.FlowHistoryEntry{}
	for _, e := range resp.GetEntries() {
		got[e.GetContainer()] = e
	}
	a := got["box-a"]
	if a == nil || a.GetTenantId() != "alice" || a.GetSrcIp() != "10.0.3.2" || a.GetDstPort() != 4444 || a.GetProtocol() != pb.FlowProtocol_FLOW_PROTOCOL_TCP || a.GetLikelyReply() {
		t.Fatalf("box-a entry = %v", a)
	}
	if resp.GetRetentionSeconds() != int64((2*time.Hour)/time.Second) {
		t.Errorf("retention = %d", resp.GetRetentionSeconds())
	}
	if resp.GetCoveredSince() == nil || resp.GetCoveredSince().AsTime().IsZero() {
		t.Error("covered_since must be set so an empty answer can be interpreted")
	}
}

// A tenant sees only its own boxes, and asking for another's is denied rather
// than silently rewritten.
func TestQueryFlowHistory_TenantIsolation(t *testing.T) {
	s := flowHistoryServer(t)
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "member")
	resp, err := s.QueryFlowHistory(ctx, &pb.QueryFlowHistoryRequest{DstIp: "93.184.216.34"})
	if err != nil {
		t.Fatalf("QueryFlowHistory: %v", err)
	}
	if len(resp.GetEntries()) != 1 || resp.GetEntries()[0].GetContainer() != "box-a" {
		t.Fatalf("entries = %v, want only alice's box", resp.GetEntries())
	}
	_, err = s.QueryFlowHistory(ctx, &pb.QueryFlowHistoryRequest{DstIp: "93.184.216.34", TenantId: "bob"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied for another tenant", status.Code(err))
	}
}

func TestQueryFlowHistory_BadInput(t *testing.T) {
	s := flowHistoryServer(t)
	ctx := auth.ContextWithTestSubject(context.Background(), "root", auth.RoleAdmin)
	for name, req := range map[string]*pb.QueryFlowHistoryRequest{
		"missing dst": {},
		"not an ip":   {DstIp: "mining.pool.example"},
		"ipv6":        {DstIp: "2001:db8::1"},
		"port range":  {DstIp: "93.184.216.34", DstPort: 70000},
	} {
		if _, err := s.QueryFlowHistory(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, status.Code(err))
		}
	}
}

func TestQueryFlowHistory_TimeWindowAndMisses(t *testing.T) {
	s := flowHistoryServer(t)
	ctx := auth.ContextWithTestSubject(context.Background(), "root", auth.RoleAdmin)
	// Entries were last seen 30 minutes ago: a since in the last 5 minutes
	// excludes them; a wrong port or address finds nothing.
	for name, req := range map[string]*pb.QueryFlowHistoryRequest{
		"since too recent": {DstIp: "93.184.216.34", Since: timestamppb.New(time.Now().Add(-5 * time.Minute))},
		"wrong port":       {DstIp: "93.184.216.34", DstPort: 5555},
		"other address":    {DstIp: "93.184.216.35"},
	} {
		resp, err := s.QueryFlowHistory(ctx, req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(resp.GetEntries()) != 0 {
			t.Errorf("%s: entries = %v, want none", name, resp.GetEntries())
		}
	}
	resp, err := s.QueryFlowHistory(ctx, &pb.QueryFlowHistoryRequest{DstIp: "93.184.216.34", Limit: 1})
	if err != nil || len(resp.GetEntries()) != 1 {
		t.Fatalf("limit 1: entries=%v err=%v", resp.GetEntries(), err)
	}
}

// An enabled log that has never received a flow poll can vouch for nothing; an
// empty answer would read as "no box did it", so it is an error.
func TestQueryFlowHistory_NoDataYetIsAnError(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFlowLog(threatdetect.NewFlowLog(time.Hour, time.Now()))
	ctx := auth.ContextWithTestSubject(context.Background(), "root", auth.RoleAdmin)
	_, err := s.QueryFlowHistory(ctx, &pb.QueryFlowHistoryRequest{DstIp: "93.184.216.34"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition when the log has received no data", status.Code(err))
	}
}
