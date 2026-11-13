package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestFlowHistoryTime(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in, want, wantErr string
	}{
		{"", "", ""},
		{"2h", "2026-11-14T10:00:00Z", ""},
		{"90m", "2026-11-14T10:30:00Z", ""},
		{"2026-11-13T16:30:00Z", "2026-11-13T16:30:00Z", ""},
		{"2026-11-13T16:30:00+08:00", "2026-11-13T08:30:00Z", ""}, // normalised to UTC
		{"-2h", "", "negative"},
		{"yesterday", "", "neither"},
	} {
		got, err := flowHistoryTime(tc.in, now)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("flowHistoryTime(%q) err = %v, want %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("flowHistoryTime(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestFlowHistoryQuery(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	q, err := flowHistoryQuery(" 91.121.106.55 ", 4444, "1h", "", "org", 20, now)
	if err != nil {
		t.Fatalf("flowHistoryQuery: %v", err)
	}
	for k, want := range map[string]string{
		"dst_ip": "91.121.106.55", "dst_port": "4444", "since": "2026-11-14T11:00:00Z", "tenant_id": "org", "limit": "20",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if q.Has("until") {
		t.Error("an unset --until must not be sent")
	}
	// Unset optional flags are not sent at all.
	q, _ = flowHistoryQuery("93.184.1.1", 0, "", "", "", 0, now)
	if len(q) != 1 || q.Get("dst_ip") != "93.184.1.1" {
		t.Errorf("minimal query = %v, want only dst_ip", q)
	}
	for name, run := range map[string]func() error{
		"hostname":     func() error { _, e := flowHistoryQuery("pool.example.com", 0, "", "", "", 0, now); return e },
		"ipv6":         func() error { _, e := flowHistoryQuery("2001:db8::1", 0, "", "", "", 0, now); return e },
		"port too big": func() error { _, e := flowHistoryQuery("93.184.1.1", 70000, "", "", "", 0, now); return e },
		"bad since":    func() error { _, e := flowHistoryQuery("93.184.1.1", 0, "soon", "", "", 0, now); return e },
	} {
		if run() == nil {
			t.Errorf("%s: want an error before any request is sent", name)
		}
	}
}

func TestRenderFlowHistory(t *testing.T) {
	ts := timestamppb.New(time.Date(2026, 11, 13, 16, 35, 0, 0, time.UTC))
	var b bytes.Buffer
	renderFlowHistory(&b, &pb.QueryFlowHistoryResponse{
		CoveredSince: ts, RetentionSeconds: 7200,
		Entries: []*pb.FlowHistoryEntry{
			{Container: "box-a", TenantId: "org", SrcIp: "10.0.3.2", DstIp: "91.121.106.55", DstPort: 4444, Protocol: "tcp", FirstSeen: ts, LastSeen: ts},
			{Container: "", TenantId: "evil\x1b[31morg", SrcIp: "10.0.3.9", DstIp: "91.121.106.55", DstPort: 51000, Protocol: "tcp", FirstSeen: ts, LastSeen: ts, LikelyReply: true},
		},
	})
	out := b.String()
	for _, want := range []string{"covers 2026-11-13T16:35:00Z onward (retention 2h0m0s)", "box-a", "(unknown box)", "reply?"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("a tenant-controlled escape sequence reached the terminal:\n%q", out)
	}
}

// An empty answer always says what the log covers, so it is not mistaken for
// "no box did it".
func TestRenderFlowHistory_EmptyStatesCoverage(t *testing.T) {
	var b bytes.Buffer
	renderFlowHistory(&b, &pb.QueryFlowHistoryResponse{CoveredSince: timestamppb.New(time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC)), RetentionSeconds: 3600})
	out := b.String()
	if !strings.Contains(out, "covers 2026-11-14T01:00:00Z onward") || !strings.Contains(out, "No box is recorded") {
		t.Errorf("empty output = %q", out)
	}
}
