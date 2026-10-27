package client

import (
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The REST shim (grpc-gateway/protojson) renders the Isolation enum as its
// name; the client maps it back onto ContainerInfo.InstanceType so every
// consumer (list, MCP) sees the same "virtual-machine"/"container" strings
// the Incus-backed path produces.
func TestContainerToIncusInfo_Isolation(t *testing.T) {
	tests := []struct {
		wire string
		want string
	}{
		{"ISOLATION_TYPE_VM", "virtual-machine"},
		{"ISOLATION_TYPE_CONTAINER", "container"},
		{"ISOLATION_TYPE_UNSPECIFIED", ""},
		{"", ""},
	}
	for _, tt := range tests {
		info := containerToIncusInfo(&containerResponse{Name: "x", Isolation: tt.wire})
		if info.InstanceType != tt.want {
			t.Errorf("wire %q → InstanceType %q, want %q", tt.wire, info.InstanceType, tt.want)
		}
	}
}

func TestIsolationMarshalsAsItsNumericEnumValue(t *testing.T) {
	b, err := json.Marshal(createContainerRequest{Isolation: pb.IsolationType_ISOLATION_TYPE_VM})
	if err != nil {
		t.Fatal(err)
	}
	want := `"isolation":` + itoa(int(pb.IsolationType_ISOLATION_TYPE_VM))
	if !strings.Contains(string(b), want) {
		t.Errorf("marshaled %s, want it to contain %s", b, want)
	}
}
