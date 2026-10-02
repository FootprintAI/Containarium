package ostype

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestParseIsolation(t *testing.T) {
	tests := []struct {
		in      string
		want    pb.IsolationType
		wantErr bool
	}{
		{"", pb.IsolationType_ISOLATION_TYPE_UNSPECIFIED, false},
		{"container", pb.IsolationType_ISOLATION_TYPE_CONTAINER, false},
		{"lxc", pb.IsolationType_ISOLATION_TYPE_CONTAINER, false},
		{"vm", pb.IsolationType_ISOLATION_TYPE_VM, false},
		{"virtual-machine", pb.IsolationType_ISOLATION_TYPE_VM, false},
		{"VM", pb.IsolationType_ISOLATION_TYPE_VM, false},
		{"bogus", pb.IsolationType_ISOLATION_TYPE_UNSPECIFIED, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseIsolation(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseIsolation(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseIsolation(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsolationFromInstanceType(t *testing.T) {
	tests := []struct {
		in   string
		want pb.IsolationType
	}{
		{"virtual-machine", pb.IsolationType_ISOLATION_TYPE_VM},
		{"container", pb.IsolationType_ISOLATION_TYPE_CONTAINER},
		{"", pb.IsolationType_ISOLATION_TYPE_UNSPECIFIED},
		{"weird", pb.IsolationType_ISOLATION_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		if got := IsolationFromInstanceType(tt.in); got != tt.want {
			t.Errorf("IsolationFromInstanceType(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestIsolationShort(t *testing.T) {
	tests := []struct {
		in   pb.IsolationType
		want string
	}{
		{pb.IsolationType_ISOLATION_TYPE_VM, "vm"},
		{pb.IsolationType_ISOLATION_TYPE_CONTAINER, "lxc"},
		{pb.IsolationType_ISOLATION_TYPE_UNSPECIFIED, "-"},
	}
	for _, tt := range tests {
		if got := IsolationShort(tt.in); got != tt.want {
			t.Errorf("IsolationShort(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
