package cmd

import (
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
