package lxc

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// newTestBackend wires an lxc.Backend over a Manager backed by the shared
// incustest.MockBackend, so delegation can be exercised without a real host.
func newTestBackend(mock *incustest.MockBackend) *Backend {
	return New(container.NewWithBackend(mock))
}

func TestKind(t *testing.T) {
	if got := New(nil).Kind(); got != box.KindLXC {
		t.Fatalf("Kind() = %q, want %q", got, box.KindLXC)
	}
}

func TestParseState(t *testing.T) {
	cases := map[string]pb.ContainerState{
		"Running": pb.ContainerState_CONTAINER_STATE_RUNNING,
		"Stopped": pb.ContainerState_CONTAINER_STATE_STOPPED,
		"Frozen":  pb.ContainerState_CONTAINER_STATE_FROZEN,
		"":        pb.ContainerState_CONTAINER_STATE_UNSPECIFIED,
		"weird":   pb.ContainerState_CONTAINER_STATE_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := parseState(in); got != want {
			t.Errorf("parseState(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTenantOf(t *testing.T) {
	if got := tenantOf(&incus.ContainerInfo{Username: "alice", Name: "alice-container"}); got != "alice" {
		t.Errorf("tenantOf with Username = %q, want alice", got)
	}
	// Falls back to stripping the -container suffix when Username is empty.
	if got := tenantOf(&incus.ContainerInfo{Name: "bob-container"}); got != "bob" {
		t.Errorf("tenantOf fallback = %q, want bob", got)
	}
}

func TestContainerName(t *testing.T) {
	if got := containerName(box.BoxRef{Tenant: "alice"}); got != "alice-container" {
		t.Errorf("containerName derived = %q, want alice-container", got)
	}
	if got := containerName(box.BoxRef{Tenant: "alice", Name: "explicit"}); got != "explicit" {
		t.Errorf("containerName explicit = %q, want explicit", got)
	}
}

func TestSpecToCreateOptions(t *testing.T) {
	spec := box.BoxSpec{
		Ref:         box.BoxRef{Tenant: "alice"},
		Image:       "ubuntu/24.04",
		OSType:      pb.OSType_OS_TYPE_UBUNTU_2404,
		Resources:   box.ResourceLimits{CPU: "2", Memory: "4GB", Disk: "20GB"},
		GPUs:        []string{"0"},
		SSHKeys:     []string{"ssh-ed25519 AAAA"},
		Labels:      map[string]string{"team": "infra"},
		Monitoring:  true,
		Stack:       "python",
		StackParams: map[string]string{"version": "3.12"},
		AutoStart:   true,
		StoragePool: "containarium-tenant-alice",
	}
	got := specToCreateOptions(spec)
	want := container.CreateOptions{
		Username:        "alice",
		Image:           "ubuntu/24.04",
		CPU:             "2",
		Memory:          "4GB",
		Disk:            "20GB",
		GPUs:            []string{"0"},
		SSHKeys:         []string{"ssh-ed25519 AAAA"},
		Labels:          map[string]string{"team": "infra"},
		OSType:          pb.OSType_OS_TYPE_UBUNTU_2404,
		Monitoring:      true,
		Stack:           "python",
		StackParameters: map[string]string{"version": "3.12"},
		AutoStart:       true,
		StoragePool:     "containarium-tenant-alice",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("specToCreateOptions mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestInfoToStatus(t *testing.T) {
	info := &incus.ContainerInfo{
		Name:      "alice-container",
		Username:  "alice",
		State:     "Running",
		IPAddress: "10.0.0.5",
		CPU:       "2",
		Memory:    "4GB",
		Disk:      "20GB",
		Labels:    map[string]string{"team": "infra"},
		BackendID: "node-a",
	}
	st := StatusFromInfo(info)
	if st.Ref != (box.BoxRef{Tenant: "alice", Name: "alice-container"}) {
		t.Errorf("Ref = %+v", st.Ref)
	}
	if st.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		t.Errorf("State = %v", st.State)
	}
	if st.IPAddress != "10.0.0.5" {
		t.Errorf("IPAddress = %q", st.IPAddress)
	}
	if st.Resources != (box.ResourceLimits{CPU: "2", Memory: "4GB", Disk: "20GB"}) {
		t.Errorf("Resources = %+v", st.Resources)
	}
	if st.BackendID != "node-a" || !reflect.DeepEqual(st.Labels, info.Labels) {
		t.Errorf("BackendID/Labels = %q / %+v", st.BackendID, st.Labels)
	}
}

func TestLifecycleDelegation(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{
		Name:      "alice-container",
		State:     "Stopped",
		IPAddress: "10.0.0.5",
	}
	b := newTestBackend(mock)
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "alice"}

	// Get
	st, err := b.Get(ctx, ref)
	if err != nil || st == nil {
		t.Fatalf("Get returned (%v, %v)", st, err)
	}
	if st.Ref.Tenant != "alice" || st.IPAddress != "10.0.0.5" {
		t.Errorf("Get status = %+v", st)
	}

	// Get of a missing box → (nil, nil)
	if missing, err := b.Get(ctx, box.BoxRef{Tenant: "ghost"}); err != nil || missing != nil {
		t.Errorf("Get(missing) = (%v, %v), want (nil, nil)", missing, err)
	}

	// List
	list, err := b.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List returned (%d, %v)", len(list), err)
	}

	// Start / Stop toggle the mock state.
	if err := b.Start(ctx, ref); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if mock.Containers["alice-container"].State != "Running" {
		t.Errorf("after Start, state = %q", mock.Containers["alice-container"].State)
	}
	if err := b.Stop(ctx, ref, false); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if mock.Containers["alice-container"].State != "Stopped" {
		t.Errorf("after Stop, state = %q", mock.Containers["alice-container"].State)
	}

	// Resolve mirrors Get's endpoint.
	ep, err := b.Resolve(ctx, ref)
	if err != nil || ep == nil || ep.DirectIP != "10.0.0.5" || ep.SSHUser != "alice" {
		t.Errorf("Resolve = (%+v, %v)", ep, err)
	}

	// Delete removes it.
	if err := b.Delete(ctx, ref, true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := mock.Containers["alice-container"]; ok {
		t.Errorf("after Delete, container still present")
	}
}

func TestResizeDelegation(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: "Running"}
	var gotDisk, gotCPU, gotMem string
	mock.SetDeviceSizeFunc = func(_, dev, size string) error {
		if dev == "root" {
			gotDisk = size
		}
		return nil
	}
	mock.SetCPULimitFunc = func(_, cpu string) error { gotCPU = cpu; return nil }
	mock.SetConfigFunc = func(_, key, val string) error {
		if key == "limits.memory" {
			gotMem = val
		}
		return nil
	}
	b := newTestBackend(mock)
	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "alice"}, box.ResourceLimits{CPU: "4", Memory: "8GB", Disk: "40GB"}); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if gotCPU != "4" || gotMem != "8GB" || gotDisk != "40GB" {
		t.Errorf("Resize delegated cpu=%q mem=%q disk=%q", gotCPU, gotMem, gotDisk)
	}
}

func TestMetaDelegation(t *testing.T) {
	mock := incustest.NewMockBackend()
	var setLabels map[string]string
	mock.SetLabelsFunc = func(_ string, labels map[string]string) error { setLabels = labels; return nil }
	mock.GetLabelsFunc = func(_ string) (map[string]string, error) {
		return map[string]string{"team": "infra"}, nil
	}
	b := newTestBackend(mock)
	ref := box.BoxRef{Tenant: "alice"}

	if err := b.SetMeta(context.Background(), ref, map[string]string{"env": "prod"}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if !reflect.DeepEqual(setLabels, map[string]string{"env": "prod"}) {
		t.Errorf("SetMeta delegated labels = %+v", setLabels)
	}

	meta, err := b.GetMeta(context.Background(), ref)
	if err != nil || !reflect.DeepEqual(meta, map[string]string{"team": "infra"}) {
		t.Errorf("GetMeta = (%+v, %v)", meta, err)
	}
}

func TestMetricsDelegation(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetContainerMetricsFunc = func(name string) (*incus.ContainerMetrics, error) {
		return &incus.ContainerMetrics{Name: name, CPUUsageSeconds: 42, MemoryUsageBytes: 1024, ProcessCount: 7}, nil
	}
	b := newTestBackend(mock)
	m, err := b.Metrics(context.Background(), box.BoxRef{Tenant: "alice"})
	if err != nil || m == nil {
		t.Fatalf("Metrics returned (%v, %v)", m, err)
	}
	if m.CPUUsageSeconds != 42 || m.MemoryUsageBytes != 1024 || m.ProcessCount != 7 {
		t.Errorf("Metrics mapping = %+v", m)
	}
}

func TestSetAuthorizedKeysDelegation(t *testing.T) {
	mock := incustest.NewMockBackend()
	var wrotePath string
	var execArgv []string
	mock.WriteFileFunc = func(_, path string, _ []byte, _ string) error {
		wrotePath = path
		return nil
	}
	mock.ExecFunc = func(_ string, command []string) error {
		execArgv = command
		return nil
	}
	b := newTestBackend(mock)
	// Empty key set exercises the delegation path (stage via file push,
	// then one placement exec) without depending on SSH key validation.
	if err := b.SetAuthorizedKeys(context.Background(), box.BoxRef{Tenant: "alice"}, nil); err != nil {
		t.Fatalf("SetAuthorizedKeys: %v", err)
	}
	// Content is staged via the file API, and the placement exec receives
	// the user's .ssh dir as a positional parameter.
	if !strings.HasSuffix(wrotePath, "authorized_keys.alice") {
		t.Errorf("staged authorized_keys written to %q", wrotePath)
	}
	if len(execArgv) < 5 || execArgv[4] != "/home/alice/.ssh" {
		t.Errorf("placement exec argv = %v, want /home/alice/.ssh as $1", execArgv)
	}
}
