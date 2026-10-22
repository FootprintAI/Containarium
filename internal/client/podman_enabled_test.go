package client

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2858: both clients carry podman_enabled into incus.ContainerInfo. The HTTP
// tag used to be a stale "dockerEnabled" and neither converter copied the
// field, so a CLI/remote reader always saw false.
func TestContainerToIncusInfo_PodmanEnabled(t *testing.T) {
	for _, want := range []bool{true, false} {
		if got := containerToIncusInfo(&containerResponse{Name: "a-container", PodmanEnabled: want}).PodmanEnabled; got != want {
			t.Errorf("http PodmanEnabled = %v, want %v", got, want)
		}
	}
}

func TestProtoLifecycleCopiesPodmanEnabled(t *testing.T) {
	for _, want := range []bool{true, false} {
		var info incus.ContainerInfo
		applyProtoLifecycle(&info, &pb.Container{PodmanEnabled: want})
		if info.PodmanEnabled != want {
			t.Errorf("grpc PodmanEnabled = %v, want %v", info.PodmanEnabled, want)
		}
	}
}
