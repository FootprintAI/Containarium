package server

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2884: a host-wide history query reveals every tenant's connection history,
// so it is admin-only (same rule as SubscribeTraffic with no container).
func TestTrafficQueryHistory_HostWideRequiresAdmin(t *testing.T) {
	srv := &TrafficServer{}
	req := &pb.QueryTrafficHistoryRequest{
		StartTime: timestamppb.New(time.Now().Add(-time.Hour)),
		DestIp:    "203.0.113.9",
	}
	_, err := srv.QueryTrafficHistory(tenantCtx("alice"), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("tenant host-wide query: got %v want PermissionDenied", err)
	}
	// An admin passes authz and reaches the store check: this server has no
	// collector, so FailedPrecondition is exactly "got past authorization".
	_, err = srv.QueryTrafficHistory(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("admin host-wide query: got %v, want FailedPrecondition (reached the store check)", err)
	}
}

// A whitespace-only container_name is not "empty": it stays on the per-box
// path, where a tenant is refused, so it cannot be used to widen the scope.
func TestTrafficQueryHistory_WhitespaceContainerNameIsNotHostWide(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.QueryTrafficHistory(tenantCtx("alice"), &pb.QueryTrafficHistoryRequest{
		ContainerName: "  ",
		StartTime:     timestamppb.New(time.Now().Add(-time.Hour)),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestTrafficQueryHistory_PersistenceOffIsReportedNotEmpty(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.QueryTrafficHistory(adminCtx(), &pb.QueryTrafficHistoryRequest{
		ContainerName: "alice-container",
		StartTime:     timestamppb.New(time.Now().Add(-time.Hour)),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v want FailedPrecondition (collector/persistence off)", err)
	}
}

func TestHistoryQueryParams_HostWideNamesMissingStart(t *testing.T) {
	_, err := historyQueryParams(&pb.QueryTrafficHistoryRequest{}, time.Now())
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "start_time is required") {
		t.Fatalf("got %v, want InvalidArgument naming start_time", err)
	}
}

func TestHistoryQueryParams(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ts := func(d time.Duration) *timestamppb.Timestamp { return timestamppb.New(now.Add(d)) }
	tests := []struct {
		name     string
		req      *pb.QueryTrafficHistoryRequest
		wantCode codes.Code
		check    func(t *testing.T, startEnd [2]time.Time)
	}{
		{"per-box defaults end to now", &pb.QueryTrafficHistoryRequest{ContainerName: "a-container", StartTime: ts(-time.Hour)}, codes.OK,
			func(t *testing.T, se [2]time.Time) {
				if !se[1].Equal(now) {
					t.Errorf("end = %v, want now (a nil end_time used to mean 1970 and matched nothing)", se[1])
				}
			}},
		{"host-wide ok at exactly 7d", &pb.QueryTrafficHistoryRequest{StartTime: ts(-7 * 24 * time.Hour), EndTime: ts(0)}, codes.OK, nil},
		{"host-wide window over 7d", &pb.QueryTrafficHistoryRequest{StartTime: ts(-7*24*time.Hour - time.Second), EndTime: ts(0)}, codes.InvalidArgument, nil},
		{"host-wide needs start", &pb.QueryTrafficHistoryRequest{EndTime: ts(0)}, codes.InvalidArgument, nil},
		{"end before start", &pb.QueryTrafficHistoryRequest{StartTime: ts(0), EndTime: ts(-time.Minute)}, codes.InvalidArgument, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := historyQueryParams(tc.req, now)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("got %v want %v", err, tc.wantCode)
			}
			if tc.check != nil {
				tc.check(t, [2]time.Time{p.StartTime, p.EndTime})
			}
		})
	}
}
