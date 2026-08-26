package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestParsePassthroughRouteProtocol(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    pb.RouteProtocol
		wantErr bool
	}{
		{"empty defaults to tcp", "", pb.RouteProtocol_ROUTE_PROTOCOL_TCP, false},
		{"tcp", "tcp", pb.RouteProtocol_ROUTE_PROTOCOL_TCP, false},
		{"udp", "udp", pb.RouteProtocol_ROUTE_PROTOCOL_UDP, false},
		{"uppercase TCP", "TCP", pb.RouteProtocol_ROUTE_PROTOCOL_TCP, false},
		{"uppercase UDP", "UDP", pb.RouteProtocol_ROUTE_PROTOCOL_UDP, false},
		{"padded", "  udp  ", pb.RouteProtocol_ROUTE_PROTOCOL_UDP, false},
		{"invalid", "http", pb.RouteProtocol_ROUTE_PROTOCOL_UNSPECIFIED, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePassthroughRouteProtocol(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parsePassthroughRouteProtocol(%q) = %v; want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestPrintPassthroughRouteJSONFormat_UsesServerTotalCount is the
// regression guard for a review finding on #1550: the JSON output
// recomputed total_count as len(routes) instead of using the server's
// actual totalCount, so the two would silently diverge the moment the
// daemon's count and the returned page disagree (e.g. once passthrough
// listing paginates).
func TestPrintPassthroughRouteJSONFormat_UsesServerTotalCount(t *testing.T) {
	routes := []*pb.PassthroughRoute{
		{ExternalPort: 9443, TargetIp: "10.0.3.150", TargetPort: 50051},
	}
	out := captureStdout(t, func() {
		if err := printPassthroughRouteJSONFormat(routes, 42); err != nil {
			t.Fatalf("printPassthroughRouteJSONFormat: %v", err)
		}
	})

	var decoded struct {
		TotalCount int `json:"total_count"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &decoded); err != nil {
		t.Fatalf("unmarshal output: %v\noutput: %s", err, out)
	}
	if decoded.TotalCount != 42 {
		t.Errorf("total_count = %d; want the server-reported 42 (got len(routes)=%d instead)", decoded.TotalCount, len(routes))
	}
}
