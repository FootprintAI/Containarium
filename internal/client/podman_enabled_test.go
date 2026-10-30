package client

import (
	"context"
	"net"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
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

type fakeContainerReadServer struct {
	pb.UnimplementedContainerServiceServer
	container *pb.Container
}

func (f *fakeContainerReadServer) ListContainers(context.Context, *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	return &pb.ListContainersResponse{Containers: []*pb.Container{f.container}}, nil
}

func (f *fakeContainerReadServer) GetContainer(context.Context, *pb.GetContainerRequest) (*pb.GetContainerResponse, error) {
	return &pb.GetContainerResponse{Container: f.container}, nil
}

func startGRPCContainerReadClient(t *testing.T, container *pb.Container) *GRPCClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterContainerServiceServer(srv, &fakeContainerReadServer{container: container})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	c, err := NewGRPCClient(lis.Addr().String(), "", true)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func lifecycleTestContainer() *pb.Container {
	return &pb.Container{
		Name:                 "lifecycle-box",
		PodmanEnabled:        true,
		MonitoringEnabled:    true,
		AutoSleepEnabled:     true,
		IdleThresholdMinutes: 23,
	}
}

func TestGRPCListContainersCopiesLifecycleFlags(t *testing.T) {
	c := startGRPCContainerReadClient(t, lifecycleTestContainer())
	containers, err := c.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("ListContainers returned %d containers, want 1", len(containers))
	}
	got := containers[0]
	if !got.PodmanEnabled || !got.MonitoringEnabled || !got.AutoSleepEnabled || got.IdleThresholdMinutes != 23 {
		t.Errorf("ListContainers lifecycle fields = {PodmanEnabled:%v MonitoringEnabled:%v AutoSleepEnabled:%v IdleThresholdMinutes:%d}, want {true true true 23}",
			got.PodmanEnabled, got.MonitoringEnabled, got.AutoSleepEnabled, got.IdleThresholdMinutes)
	}
}

func TestGRPCGetContainerCopiesLifecycleFlags(t *testing.T) {
	c := startGRPCContainerReadClient(t, lifecycleTestContainer())
	got, err := c.GetContainer("lifecycle-box")
	if err != nil {
		t.Fatalf("GetContainer: %v", err)
	}
	if !got.PodmanEnabled || !got.MonitoringEnabled || !got.AutoSleepEnabled || got.IdleThresholdMinutes != 23 {
		t.Errorf("GetContainer lifecycle fields = {PodmanEnabled:%v MonitoringEnabled:%v AutoSleepEnabled:%v IdleThresholdMinutes:%d}, want {true true true 23}",
			got.PodmanEnabled, got.MonitoringEnabled, got.AutoSleepEnabled, got.IdleThresholdMinutes)
	}
}
