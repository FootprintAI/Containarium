package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/capabilities"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// capabilityTestResources supplies complete host facts without a live Incus daemon.
func capabilityTestResources() (*incus.SystemResources, error) {
	return &incus.SystemResources{TotalCPUs: 8, TotalMemoryBytes: 16 << 30, TotalDiskBytes: 100 << 30}, nil
}

// TestCapabilityResourceDiscoveryFailure checks automatic failure and explicit retry.
func TestCapabilityResourceDiscoveryFailure(t *testing.T) {
	for _, failure := range []string{"error", "empty", "zero CPU", "zero memory"} {
		t.Run(failure, func(t *testing.T) {
			srv := &ContainerServer{capabilityResources: func() (*incus.SystemResources, error) {
				switch failure {
				case "error":
					return nil, errors.New("resource lookup failed")
				case "empty":
					return nil, nil
				case "zero CPU":
					return &incus.SystemResources{TotalMemoryBytes: 16 << 30}, nil
				default:
					return &incus.SystemResources{TotalCPUs: 8}, nil
				}
			}}
			ds := &DualServer{config: &DualServerConfig{Pool: "test-pool"}, containerServer: srv}
			<-ds.startCapabilityProfile(context.Background())
			if _, ok := srv.capabStore().Current(); ok {
				t.Fatal("resource discovery failure must not record a profile")
			}
			ctx := auth.ContextWithSystemIdentity(context.Background())
			if _, err := srv.ProfileBackend(ctx, &pb.ProfileBackendRequest{SkipGpu: true}); status.Code(err) != codes.Internal {
				t.Fatalf("explicit profile must reject unavailable resources: %v", err)
			}
			srv.capabilityResources = capabilityTestResources
			got, err := srv.ProfileBackend(ctx, &pb.ProfileBackendRequest{SkipGpu: true})
			if err != nil || got.Profile == nil || got.Profile.CpuCores != 8 || got.Profile.TotalMemoryBytes != 16<<30 {
				t.Fatalf("explicit retry must record real host facts: %v, %v", got, err)
			}
		})
	}
}

// TestPoolMemberAutomaticallyProfiles checks that a pool member records a queryable profile without an RPC.
func TestPoolMemberAutomaticallyProfiles(t *testing.T) {
	srv := &ContainerServer{capabilityResources: func() (*incus.SystemResources, error) {
		return &incus.SystemResources{TotalCPUs: 8, TotalMemoryBytes: 16 << 30}, nil
	}}
	srv.SetCapabilityIdentity("region-a", "cpu-small")
	ds := &DualServer{config: &DualServerConfig{Pool: "cpu-small"}, containerServer: srv}
	done := ds.startCapabilityProfile(context.Background())
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("automatic profile did not finish")
	}
	got, err := srv.GetCapabilityProfile(auth.ContextWithSystemIdentity(context.Background()), &pb.GetCapabilityProfileRequest{})
	if err != nil || got.Profile == nil || got.Profile.Region != "region-a" || got.Profile.Benchmark.CpuOpsPerSec <= 0 {
		t.Fatalf("pool startup must record a readable profile: %v, %v", got, err)
	}
}

// TestPoolProfileFailureIsBestEffortAndExplicitRetryWorks checks that failed startup measurements leave no profile and allow explicit retry.
func TestPoolProfileFailureIsBestEffortAndExplicitRetryWorks(t *testing.T) {
	for _, failure := range []string{"benchmark", "invalid benchmark", "GPU probe"} {
		t.Run(failure, func(t *testing.T) {
			srv := &ContainerServer{capabilityResources: func() (*incus.SystemResources, error) {
				return &incus.SystemResources{TotalCPUs: 8, TotalMemoryBytes: 16 << 30, GPUs: []incus.GPUInfo{{Vendor: "NVIDIA Corporation"}}}, nil
			}}
			switch failure {
			case "benchmark":
				srv.capabilityBenchmark = func() (container.BenchmarkResult, error) {
					return container.BenchmarkResult{}, errors.New("benchmark failed")
				}
			case "invalid benchmark":
				srv.capabilityBenchmark = func() (container.BenchmarkResult, error) {
					return container.BenchmarkResult{}, nil
				}
			default:
				srv.capabilityGPUProbe = func() container.GPUValidationResult {
					return container.GPUValidationResult{Status: container.GPUStatusUnavailable, Detail: "probe failed"}
				}
			}
			ds := &DualServer{config: &DualServerConfig{Pool: "test-pool"}, containerServer: srv}
			<-ds.startCapabilityProfile(context.Background())
			if _, ok := srv.capabStore().Current(); ok {
				t.Fatal("failed measurement must leave no profile")
			}
			srv.capabilityBenchmark = nil
			srv.capabilityGPUProbe = nil
			got, err := srv.ProfileBackend(auth.ContextWithSystemIdentity(context.Background()), &pb.ProfileBackendRequest{SkipGpu: true})
			if err != nil || got.Profile == nil {
				t.Fatalf("explicit retry: %v, %v", got, err)
			}
		})
	}
}

// TestCapabilityProfileNVIDIAVendorID checks that an NVIDIA PCI vendor ID triggers GPU validation.
func TestCapabilityProfileNVIDIAVendorID(t *testing.T) {
	srv := &ContainerServer{
		capabilityResources: func() (*incus.SystemResources, error) {
			return &incus.SystemResources{TotalCPUs: 8, TotalMemoryBytes: 16 << 30, GPUs: []incus.GPUInfo{{Vendor: "10de"}}}, nil
		},
		capabilityGPUProbe: func() container.GPUValidationResult {
			return container.GPUValidationResult{Status: container.GPUStatusOK, Model: "test GPU", DriverVersion: "test driver"}
		},
	}
	ds := &DualServer{config: &DualServerConfig{Pool: "test-pool"}, containerServer: srv}
	<-ds.startCapabilityProfile(context.Background())
	p, ok := srv.capabStore().Current()
	if !ok || !p.GPUAvailable || p.GPUModel != "test GPU" || p.MeasuredClass != "gpu" {
		t.Fatalf("NVIDIA vendor ID must trigger GPU validation: %+v", p)
	}
}

// TestCapabilityProfileCPUOnlySkipsGPUProbe checks that CPU-only profiling does not create a GPU validation instance.
func TestCapabilityProfileCPUOnlySkipsGPUProbe(t *testing.T) {
	srv := &ContainerServer{
		capabilityResources: func() (*incus.SystemResources, error) {
			return &incus.SystemResources{TotalCPUs: 8, TotalMemoryBytes: 16 << 30}, nil
		},
		capabilityGPUProbe: func() container.GPUValidationResult {
			t.Error("CPU-only host must not launch a GPU probe")
			return container.GPUValidationResult{Status: container.GPUStatusUnavailable, Detail: "no GPU"}
		},
	}
	ds := &DualServer{config: &DualServerConfig{Pool: "test-pool"}, containerServer: srv}
	<-ds.startCapabilityProfile(context.Background())
	p, ok := srv.capabStore().Current()
	if !ok || p.GPUAvailable || p.CPUCores != 8 || p.MeasuredClass != "cpu-small" {
		t.Fatalf("CPU-only host must record a CPU profile: %+v", p)
	}
}

// TestPoolProfilePreservesExistingButExplicitProfileReplacesIt checks automatic preservation and intentional explicit replacement.
func TestPoolProfilePreservesExistingButExplicitProfileReplacesIt(t *testing.T) {
	srv := &ContainerServer{capabilityResources: capabilityTestResources}
	srv.capabStore().Record(capabilities.HostFacts{Region: "original", Now: time.Unix(100, 0)})
	srv.SetCapabilityIdentity("new-region", "")
	ds := &DualServer{config: &DualServerConfig{Pool: "test-pool"}, containerServer: srv}
	<-ds.startCapabilityProfile(context.Background())
	p, _ := srv.capabStore().Current()
	if p.Region != "original" || !p.ProfiledAt.Equal(time.Unix(100, 0)) {
		t.Fatalf("existing profile overwritten: %+v", p)
	}
	got, err := srv.ProfileBackend(auth.ContextWithSystemIdentity(context.Background()), &pb.ProfileBackendRequest{SkipGpu: true})
	if err != nil || got.Profile.Region != "new-region" {
		t.Fatalf("explicit re-profile: %v, %v", got, err)
	}
}

// TestPoolProfileDoesNotBlockStartup checks background startup and serialization with explicit profiling.
func TestPoolProfileDoesNotBlockStartup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := &ContainerServer{capabilityResources: capabilityTestResources, capabilityBenchmark: func() (container.BenchmarkResult, error) {
		close(entered)
		<-release
		return container.BenchmarkResult{CPUOpsPerSec: 1, MemBytesPerSec: 1, DurationMs: 1}, nil
	}}
	ds := &DualServer{config: &DualServerConfig{Pool: "test-pool"}, containerServer: srv}
	returned := make(chan (<-chan struct{}), 1)
	go func() { returned <- ds.startCapabilityProfile(context.Background()) }()
	var done <-chan struct{}
	defer func() {
		close(release)
		if done != nil {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("profile did not finish after releasing benchmark")
			}
		}
	}()
	select {
	case done = <-returned:
		select {
		case <-done:
			t.Fatal("measurement finished while benchmark blocked")
		default:
		}
	case <-time.After(time.Second):
		t.Fatal("profiling blocks startup")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("benchmark not started")
	}
	// The startup measurement shares the explicit RPC's serialization guard.
	_, err := srv.ProfileBackend(auth.ContextWithSystemIdentity(context.Background()), &pb.ProfileBackendRequest{SkipGpu: true})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("concurrent explicit profile must not stack another benchmark: %v", err)
	}
}

// TestUnpooledDaemonDoesNotAutomaticallyProfile checks that standalone daemons do not start automatic profiling.
func TestUnpooledDaemonDoesNotAutomaticallyProfile(t *testing.T) {
	srv := &ContainerServer{}
	ds := &DualServer{config: &DualServerConfig{}, containerServer: srv}
	<-ds.startCapabilityProfile(context.Background())
	if _, ok := srv.capabStore().Current(); ok {
		t.Fatal("unpooled daemon automatically profiled")
	}
}

// The capability-profile RPCs (#681) are admin-only: they read/record a
// fleet-level hardware signal, not a tenant resource.

func TestProfileBackend_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.ProfileBackend(ctx, &pb.ProfileBackendRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

func TestGetCapabilityProfile_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.GetCapabilityProfile(ctx, &pb.GetCapabilityProfileRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

// GetCapabilityProfile before any ProfileBackend returns a null profile (not an
// error) so the control plane can tell "unprofiled" from "profiled".
func TestGetCapabilityProfile_NullBeforeProfiling(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithSystemIdentity(context.Background())
	resp, err := srv.GetCapabilityProfile(ctx, &pb.GetCapabilityProfileRequest{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.Profile != nil {
		t.Fatalf("expected null profile before profiling; got %+v", resp.Profile)
	}
}

// TestProfileBackendRecordsAndPersists records complete host facts and a real
// bounded benchmark, then retrieves the profile without a live Incus daemon.
func TestProfileBackendRecordsAndPersists(t *testing.T) {
	srv := &ContainerServer{capabilityResources: capabilityTestResources}
	srv.SetCapabilityIdentity("region-a", "")
	ctx := auth.ContextWithSystemIdentity(context.Background())

	rec, err := srv.ProfileBackend(ctx, &pb.ProfileBackendRequest{SkipGpu: true})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if rec.Profile == nil {
		t.Fatalf("profile response must carry a profile")
	}
	if rec.Profile.Region != "region-a" {
		t.Fatalf("region = %q, want region-a", rec.Profile.Region)
	}
	// Empty reported class is treated as consistent.
	if !rec.Profile.ClassConsistent {
		t.Fatalf("empty reported class must reconcile as consistent; got %+v", rec.Profile)
	}
	if rec.Profile.Benchmark == nil || rec.Profile.Benchmark.CpuOpsPerSec <= 0 {
		t.Fatalf("benchmark must run and report positive CPU score; got %+v", rec.Profile.Benchmark)
	}
	if rec.Profile.ProfiledAt == "" {
		t.Fatalf("profiledAt must be stamped")
	}

	got, err := srv.GetCapabilityProfile(ctx, &pb.GetCapabilityProfileRequest{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Profile == nil || got.Profile.Region != "region-a" {
		t.Fatalf("get after profile must return the persisted profile; got %+v", got.Profile)
	}
}

func TestCapabilityRefreshHardwareChange(t *testing.T) {
	res := &incus.SystemResources{TotalCPUs: 8, TotalMemoryBytes: 16 << 30}
	calls := 0
	fail := false
	srv := &ContainerServer{capabilityResources: func() (*incus.SystemResources, error) { return res, nil }, capabilityBenchmark: func() (container.BenchmarkResult, error) {
		calls++
		if fail {
			return container.BenchmarkResult{}, errors.New("failed")
		}
		return container.BenchmarkResult{CPUOpsPerSec: 100, MemBytesPerSec: 100, DurationMs: 1}, nil
	}}
	if _, err := srv.recordCapabilityProfile(true, false); err != nil {
		t.Fatal(err)
	}
	if err := srv.refreshCapabilityProfile(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("unchanged hardware was benchmarked again")
	}
	res.TotalCPUs = 16
	fail = true
	if err := srv.refreshCapabilityProfile(); err == nil {
		t.Fatal("expected benchmark failure")
	}
	if _, ok := srv.capabStore().Current(); ok {
		t.Fatal("obsolete profile remains available")
	}
	fail = false
	if err := srv.refreshCapabilityProfile(); err != nil {
		t.Fatal(err)
	}
	p, ok := srv.capabStore().Current()
	if !ok || p.CPUCores != 16 {
		t.Fatal("new hardware was not recorded")
	}
}

func TestCapabilityChecksCancellation(t *testing.T) {
	ds := &DualServer{config: &DualServerConfig{Pool: "test"}, containerServer: &ContainerServer{capabilityResources: capabilityTestResources}}
	ctx, cancel := context.WithCancel(context.Background())
	done := ds.startCapabilityChecks(ctx, time.Hour)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("checks did not stop")
	}
}

func TestCapabilityRefreshDiscoveryFailurePreservesProfile(t *testing.T) {
	srv := &ContainerServer{capabilityResources: capabilityTestResources, capabilityBenchmark: func() (container.BenchmarkResult, error) {
		return container.BenchmarkResult{CPUOpsPerSec: 1, MemBytesPerSec: 1, DurationMs: 1}, nil
	}}
	original, err := srv.recordCapabilityProfile(true, false)
	if err != nil {
		t.Fatal(err)
	}
	srv.capabilityResources = func() (*incus.SystemResources, error) { return nil, errors.New("offline") }
	if err := srv.refreshCapabilityProfile(); err == nil {
		t.Fatal("expected discovery error")
	}
	current, ok := srv.capabStore().Current()
	if !ok || current.CPUCores != original.CPUCores {
		t.Fatal("unconfirmed change invalidated profile")
	}
}

func TestCapabilityHardwareKeyIgnoresUtilizationAndGPUOrder(t *testing.T) {
	a := incus.SystemResources{TotalCPUs: 8, TotalMemoryBytes: 16 << 30, GPUs: []incus.GPUInfo{{Model: "A"}, {Model: "B"}}}
	b := a
	b.UsedMemoryBytes = 1024
	b.UsedDiskBytes = 1024
	b.GPUs = []incus.GPUInfo{a.GPUs[1], a.GPUs[0]}
	if capabilityHardwareKey(&a) != capabilityHardwareKey(&b) {
		t.Fatal("transient state changed hardware key")
	}
	b.GPUs[0].Model = "replacement"
	if capabilityHardwareKey(&a) == capabilityHardwareKey(&b) {
		t.Fatal("GPU change was missed")
	}
}

func TestCapabilityChecksTickerRecordsProfile(t *testing.T) {
	measured := make(chan struct{}, 1)
	srv := &ContainerServer{capabilityResources: capabilityTestResources, capabilityBenchmark: func() (container.BenchmarkResult, error) {
		measured <- struct{}{}
		return container.BenchmarkResult{CPUOpsPerSec: 1, MemBytesPerSec: 1, DurationMs: 1}, nil
	}}
	ds := &DualServer{config: &DualServerConfig{Pool: "test"}, containerServer: srv}
	ctx, cancel := context.WithCancel(context.Background())
	done := ds.startCapabilityChecks(ctx, time.Millisecond)
	defer func() { cancel(); <-done }()
	select {
	case <-measured:
	case <-time.After(time.Second):
		t.Fatal("ticker did not measure hardware")
	}
}
