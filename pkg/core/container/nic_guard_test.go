package container

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// recordingGuard records what the manager asked it to guard, and can fail.
type recordingGuard struct {
	calls []string // "container|tenant"
	err   error
}

func (g *recordingGuard) Prepare(_ context.Context, name, tenant string) error {
	g.calls = append(g.calls, name+"|"+tenant)
	return g.err
}

// guardBackend is stagesBackend plus a started flag so the order
// (Prepare before StartContainer) can be asserted.
type guardBackend struct {
	*stagesBackend
	started bool
}

func (b *guardBackend) StartContainer(string) error { b.started = true; return nil }

func TestCreate_GuardsNICBeforeStart(t *testing.T) {
	b := &guardBackend{stagesBackend: &stagesBackend{}}
	m := NewWithBackend(b)
	g := &recordingGuard{}
	m.SetNICGuard(g)

	opts := stagesOpts()
	opts.Labels = map[string]string{incus.CloudOrgIDLabel: "org-a"}
	if _, err := m.Create(opts); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(g.calls) != 1 || g.calls[0] != opts.Username+"-container|org-a" {
		t.Errorf("guard calls = %v", g.calls)
	}
	if !b.started {
		t.Fatal("container never started")
	}
}

func TestCreate_GuardOrderAndNameFallback(t *testing.T) {
	sb := &stagesBackend{}
	b := &guardBackend{stagesBackend: sb}
	m := NewWithBackend(b)
	// Prepare must observe the container not yet started.
	g := &recordingGuard{}
	var startedAtPrepare *bool
	m.SetNICGuard(guardFunc(func(_ context.Context, name, tenant string) error {
		v := b.started
		startedAtPrepare = &v
		g.calls = append(g.calls, name+"|"+tenant)
		return nil
	}))
	opts := stagesOpts() // no labels: tenant comes from the <tenant>-container name
	if _, err := m.Create(opts); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if startedAtPrepare == nil || *startedAtPrepare {
		t.Error("Prepare ran after StartContainer")
	}
	if len(g.calls) != 1 || g.calls[0] != opts.Username+"-container|"+opts.Username {
		t.Errorf("guard calls = %v", g.calls)
	}
}

func TestCreate_GuardFailureDeletesAndFailsClosed(t *testing.T) {
	sb := &stagesBackend{}
	b := &guardBackend{stagesBackend: sb}
	m := NewWithBackend(b)
	m.SetNICGuard(&recordingGuard{err: errors.New("incus: acl boom")})

	_, err := m.Create(stagesOpts())
	if !errors.Is(err, ErrNICGuard) {
		t.Fatalf("err = %v, want ErrNICGuard", err)
	}
	if b.started {
		t.Error("container was started although the guard failed")
	}
	if sb.deleteCalls != 1 {
		t.Errorf("deleteCalls = %d, want 1 (fail closed: the box is removed)", sb.deleteCalls)
	}
}

func TestCreate_NoGuardIsNoop(t *testing.T) {
	b := &guardBackend{stagesBackend: &stagesBackend{}}
	m := NewWithBackend(b)
	if _, err := m.Create(stagesOpts()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !b.started {
		t.Error("container not started")
	}
}

type guardFunc func(ctx context.Context, name, tenant string) error

func (f guardFunc) Prepare(ctx context.Context, name, tenant string) error {
	return f(ctx, name, tenant)
}
