package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeSandboxBackend is a minimal, map-backed incus.Backend fake: real
// enough that GetContainer after CreateContainer sees the labels/tenant
// the create call stamped, without depending on a live Incus daemon.
//
// mu guards instances/deleteCalls: pool.Reconcile warms multiple members
// for the same template concurrently (one goroutine per warm, see
// pool.go's Reconcile), so any test with min_warm > 1 drives concurrent
// CreateContainer/StartContainer calls into this single fake — without a
// lock that's a genuine, `-race`-catchable data race, not just a
// theoretical one.
type fakeSandboxBackend struct {
	incus.Backend
	mu        sync.Mutex
	instances map[string]incus.ContainerInfo

	waitNetworkErr     error
	execStdout         string
	execStderr         string
	execExitCode       int
	execErr            error
	writeFileErr       error
	readFileContent    []byte
	readFileErr        error
	deleteContainerErr error
	deleteCalls        int
	startErr           error
	setLabelsErr       error
	setConfigErr       error
}

func newFakeSandboxBackend() *fakeSandboxBackend {
	return &fakeSandboxBackend{instances: make(map[string]incus.ContainerInfo)}
}

func (b *fakeSandboxBackend) CreateContainer(c incus.ContainerConfig) error {
	info := incus.ContainerInfo{
		Name:   c.Name,
		State:  "Stopped",
		Labels: extractTestLabels(c.ExtraConfig),
		Tenant: c.ExtraConfig[incus.TenantLabelKey],
		Image:  c.Image,
	}
	if raw := c.ExtraConfig[incus.TTLExpiresAtKey]; raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			info.TTLExpiresAt = t
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.instances[c.Name] = info
	return nil
}

// ListContainers returns every tracked instance, mirroring the real
// backend closely enough for ttlsweeperSandboxAdapter's tests: it reads
// exactly (Name, Labels, TTLExpiresAt), all of which CreateContainer/
// SetConfig/SetLabels already populate above.
func (b *fakeSandboxBackend) ListContainers() ([]incus.ContainerInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]incus.ContainerInfo, 0, len(b.instances))
	for _, info := range b.instances {
		out = append(out, info)
	}
	return out, nil
}

// extractTestLabels mirrors incus's own LabelPrefix-stripping so the fake's
// GetContainer sees the same view a real backend would.
func extractTestLabels(config map[string]string) map[string]string {
	labels := make(map[string]string)
	for k, v := range config {
		if len(k) > len(incus.LabelPrefix) && k[:len(incus.LabelPrefix)] == incus.LabelPrefix {
			labels[k[len(incus.LabelPrefix):]] = v
		}
	}
	return labels
}

func (b *fakeSandboxBackend) StartContainer(name string) error {
	if b.startErr != nil {
		return b.startErr
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if info, ok := b.instances[name]; ok {
		info.State = "Running"
		b.instances[name] = info
	}
	return nil
}

func (b *fakeSandboxBackend) StopContainer(string, bool) error { return nil }

func (b *fakeSandboxBackend) DeleteContainer(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deleteCalls++
	if b.deleteContainerErr != nil {
		return b.deleteContainerErr
	}
	delete(b.instances, name)
	return nil
}

func (b *fakeSandboxBackend) WaitForNetwork(string, time.Duration) (string, error) {
	if b.waitNetworkErr != nil {
		return "", b.waitNetworkErr
	}
	return "203.0.113.9", nil
}

func (b *fakeSandboxBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	info, ok := b.instances[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return &info, nil
}

func (b *fakeSandboxBackend) ExecWithExitCode(string, []string) (string, string, int, error) {
	return b.execStdout, b.execStderr, b.execExitCode, b.execErr
}

func (b *fakeSandboxBackend) WriteFile(string, string, []byte, string) error {
	return b.writeFileErr
}

func (b *fakeSandboxBackend) ReadFile(string, string) ([]byte, error) {
	return b.readFileContent, b.readFileErr
}

// SetConfig mirrors the real client's semantics closely enough for these
// tests: TenantLabelKey and TTLExpiresAtKey are the only raw keys
// claimFromPool sets this way, so those are the only ones this fake
// bothers reflecting back into ContainerInfo.
func (b *fakeSandboxBackend) SetConfig(name, key, value string) error {
	if b.setConfigErr != nil {
		return b.setConfigErr
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	info, ok := b.instances[name]
	if !ok {
		return errors.New("not found")
	}
	switch key {
	case incus.TenantLabelKey:
		info.Tenant = value
	case incus.TTLExpiresAtKey:
		t, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return err
		}
		info.TTLExpiresAt = t
	}
	b.instances[name] = info
	return nil
}

// SetLabels mirrors the real client's clear-then-replace semantics: every
// existing label-prefixed key is dropped, then only what's in labels (bare
// keys, per the real SetLabels contract) is re-added. Getting this
// mirroring wrong would hide the exact double-prefix bug this fake exists
// to catch.
func (b *fakeSandboxBackend) SetLabels(name string, labels map[string]string) error {
	if b.setLabelsErr != nil {
		return b.setLabelsErr
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	info, ok := b.instances[name]
	if !ok {
		return errors.New("not found")
	}
	info.Labels = make(map[string]string, len(labels))
	for k, v := range labels {
		info.Labels[k] = v
	}
	b.instances[name] = info
	return nil
}

func ctxAs(username string, admin bool) context.Context {
	roles := []string{}
	if admin {
		roles = []string{auth.RoleAdmin}
	}
	return auth.ContextWithClaims(context.Background(), &auth.Claims{Username: username, Roles: roles})
}

func spawnAsAlice(t *testing.T, backend *fakeSandboxBackend, s *SandboxServer) *pb.Sandbox {
	t.Helper()
	resp, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if err != nil {
		t.Fatalf("SpawnSandbox: %v", err)
	}
	return resp.Sandbox
}

func TestSpawnSandbox_HappyPath(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)

	sb := spawnAsAlice(t, backend, s)

	if sb.SandboxId == "" {
		t.Fatal("empty sandbox_id")
	}
	if sb.State != pb.SandboxState_SANDBOX_STATE_RUNNING {
		t.Errorf("state = %v, want RUNNING", sb.State)
	}
	if sb.Template != pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE {
		t.Errorf("template = %v, want BASE (unspecified should resolve to BASE)", sb.Template)
	}
	if sb.ServedFrom != pb.ServedFrom_SERVED_FROM_COLD {
		t.Errorf("served_from = %v, want COLD (Phase 1 has no pool)", sb.ServedFrom)
	}
	if sb.CreatedAt == nil || sb.ExpiresAt == nil {
		t.Error("created_at / expires_at not set")
	}

	info := backend.instances[sb.SandboxId]
	if info.Tenant != "alice" {
		t.Errorf("stamped tenant = %q, want alice", info.Tenant)
	}
	if info.Labels[sandboxKindLabelSuffix] != SandboxKindLabelValue {
		t.Errorf("sandbox-kind label not stamped: %+v", info.Labels)
	}
}

func TestSpawnSandbox_UnauthenticatedRejected(t *testing.T) {
	s := NewSandboxServer(newFakeSandboxBackend(), nil)
	if _, err := s.SpawnSandbox(context.Background(), &pb.SpawnSandboxRequest{}); err == nil {
		t.Fatal("SpawnSandbox with no subject in context should fail")
	}
}

func TestSpawnSandbox_UnsupportedTemplateRejected(t *testing.T) {
	s := NewSandboxServer(newFakeSandboxBackend(), nil)
	_, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{Template: pb.SandboxTemplate(99)})
	if err == nil {
		t.Fatal("unsupported template should be rejected — v1 ships BASE only")
	}
}

// TestSpawnSandbox_NetworkFailureCleansUp pins the rollback contract: a
// spawn that fails after CreateContainer/StartContainer must not leave the
// half-provisioned instance behind.
func TestSpawnSandbox_NetworkFailureCleansUp(t *testing.T) {
	backend := newFakeSandboxBackend()
	backend.waitNetworkErr = errors.New("no lease")
	s := NewSandboxServer(backend, nil)

	if _, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{}); err == nil {
		t.Fatal("SpawnSandbox should fail when WaitForNetwork fails")
	}
	if backend.deleteCalls == 0 {
		t.Error("failed spawn did not clean up the half-provisioned instance")
	}
}

// TestSandboxOwnership pins the design note's own required contract: a
// cross-tenant sandbox_id resolves to PermissionDenied, never NotFound —
// the ownership check must run before existence can leak.
func TestSandboxOwnership(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	t.Run("owner can exec", func(t *testing.T) {
		if _, err := s.ExecInSandbox(ctxAs("alice", false), &pb.ExecInSandboxRequest{
			SandboxId: sb.SandboxId, Command: []string{"true"},
		}); err != nil {
			t.Errorf("owner exec: %v", err)
		}
	})

	t.Run("different tenant gets PermissionDenied, not NotFound", func(t *testing.T) {
		_, err := s.ExecInSandbox(ctxAs("bob", false), &pb.ExecInSandboxRequest{
			SandboxId: sb.SandboxId, Command: []string{"true"},
		})
		if got := status.Code(err); got != codes.PermissionDenied {
			t.Errorf("code = %v, want PermissionDenied (cross-tenant access must not read as NotFound)", got)
		}
	})

	t.Run("admin can exec any tenant's sandbox", func(t *testing.T) {
		if _, err := s.ExecInSandbox(ctxAs("root", true), &pb.ExecInSandboxRequest{
			SandboxId: sb.SandboxId, Command: []string{"true"},
		}); err != nil {
			t.Errorf("admin exec: %v", err)
		}
	})

	t.Run("nonexistent sandbox_id is NotFound", func(t *testing.T) {
		_, err := s.ExecInSandbox(ctxAs("alice", false), &pb.ExecInSandboxRequest{
			SandboxId: "sandbox-does-not-exist", Command: []string{"true"},
		})
		if got := status.Code(err); got != codes.NotFound {
			t.Errorf("code = %v, want NotFound", got)
		}
	})
}

func TestExecInSandbox_ReturnsExitCode(t *testing.T) {
	backend := newFakeSandboxBackend()
	backend.execStdout = "hello\n"
	backend.execStderr = "warn\n"
	backend.execExitCode = 3
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	resp, err := s.ExecInSandbox(ctxAs("alice", false), &pb.ExecInSandboxRequest{
		SandboxId: sb.SandboxId, Command: []string{"false"},
	})
	if err != nil {
		t.Fatalf("ExecInSandbox: %v", err)
	}
	if resp.Stdout != "hello\n" || resp.Stderr != "warn\n" || resp.ExitCode != 3 {
		t.Errorf("resp = %+v, want stdout=hello stderr=warn exit_code=3", resp)
	}
}

func TestExecInSandbox_RequiresCommand(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	if _, err := s.ExecInSandbox(ctxAs("alice", false), &pb.ExecInSandboxRequest{SandboxId: sb.SandboxId}); err == nil {
		t.Fatal("empty command should be rejected")
	}
}

func TestWriteReadFileInSandbox_RoundTrip(t *testing.T) {
	backend := newFakeSandboxBackend()
	backend.readFileContent = []byte("round-tripped")
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	if _, err := s.WriteFileInSandbox(ctxAs("alice", false), &pb.WriteFileInSandboxRequest{
		SandboxId: sb.SandboxId, Path: "/workspace/out.txt", Content: []byte("data"),
	}); err != nil {
		t.Fatalf("WriteFileInSandbox: %v", err)
	}

	resp, err := s.ReadFileInSandbox(ctxAs("alice", false), &pb.ReadFileInSandboxRequest{
		SandboxId: sb.SandboxId, Path: "/workspace/out.txt",
	})
	if err != nil {
		t.Fatalf("ReadFileInSandbox: %v", err)
	}
	if string(resp.Content) != "round-tripped" {
		t.Errorf("content = %q", resp.Content)
	}

	t.Run("cross-tenant read denied", func(t *testing.T) {
		if _, err := s.ReadFileInSandbox(ctxAs("bob", false), &pb.ReadFileInSandboxRequest{
			SandboxId: sb.SandboxId, Path: "/workspace/out.txt",
		}); err == nil {
			t.Fatal("expected PermissionDenied for a different tenant's sandbox")
		}
	})
}

func TestDeleteSandbox_Destroys(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	if _, err := s.DeleteSandbox(ctxAs("alice", false), &pb.DeleteSandboxRequest{SandboxId: sb.SandboxId}); err != nil {
		t.Fatalf("DeleteSandbox: %v", err)
	}
	if _, ok := backend.instances[sb.SandboxId]; ok {
		t.Error("sandbox still present after DeleteSandbox")
	}

	t.Run("second delete is NotFound, not a crash", func(t *testing.T) {
		if _, err := s.DeleteSandbox(ctxAs("alice", false), &pb.DeleteSandboxRequest{SandboxId: sb.SandboxId}); err == nil {
			t.Fatal("deleting an already-deleted sandbox should error")
		}
	})
}

// TestDeleteSandbox_DeleteErrorPropagates pins the fix over the naive
// best-effort version: DeleteSandbox is the caller's explicit request to
// delete, so a real DeleteContainer failure must surface, not be silently
// swallowed the way a failed-spawn rollback discards it.
func TestDeleteSandbox_DeleteErrorPropagates(t *testing.T) {
	backend := newFakeSandboxBackend()
	backend.deleteContainerErr = errors.New("incus: instance is busy")
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	if _, err := s.DeleteSandbox(ctxAs("alice", false), &pb.DeleteSandboxRequest{SandboxId: sb.SandboxId}); err == nil {
		t.Fatal("DeleteSandbox should surface a real DeleteContainer failure")
	}
}
