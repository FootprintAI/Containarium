package container

import (
	"errors"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/ostype"
)

// #1530: the benchmark investigation found installPackages waited a fixed
// 5s "for cloud-init to finish" on every create, even against
// images:ubuntu/24.04 — this daemon's default create base — which doesn't
// ship cloud-init at all. Pure waste on every stackless create. These tests
// cover cloudInitPresent directly, and installPackages' use of it.

// cloudInitProbeBackend fakes exactly the two calls installPackages makes
// before this fix's guard point: the cloud-init presence probe
// (ExecWithExitCode) and, immediately after, a package-repo update (Exec) —
// deliberately failing that second call so installPackages returns right
// after the sleep-or-skip decision, without needing to fake the rest of a
// full package install.
type cloudInitProbeBackend struct {
	incus.Backend
	probeExitCode int
	probeErr      error
}

func (b *cloudInitProbeBackend) ExecWithExitCode(_ string, _ []string) (string, string, int, error) {
	return "", "", b.probeExitCode, b.probeErr
}

func (b *cloudInitProbeBackend) Exec(_ string, _ []string) error {
	return errors.New("stop here: installPackages progressed past the cloud-init wait")
}

func TestCloudInitPresent(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		err      error
		want     bool
	}{
		{"cloud-init on PATH", 0, nil, true},
		{"command not found", 1, nil, false},
		{"exec transport failure", 0, errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewWithBackend(&cloudInitProbeBackend{probeExitCode: tt.exitCode, probeErr: tt.err})
			if got := m.cloudInitPresent("box-container"); got != tt.want {
				t.Errorf("cloudInitPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInstallPackages_SkipsWaitWhenCloudInitAbsent(t *testing.T) {
	m := NewWithBackend(&cloudInitProbeBackend{probeExitCode: 1}) // `command -v cloud-init` not found
	m.cloudInitWait = 2 * time.Second                             // would show up in elapsed if hit

	start := time.Now()
	_ = m.installPackages("box-container", false, "", nil, "alice", ostype.Debian)
	elapsed := time.Since(start)

	if elapsed >= m.cloudInitWait {
		t.Errorf("installPackages took %v — cloud-init absent must skip the wait entirely", elapsed)
	}
}

func TestInstallPackages_WaitsWhenCloudInitPresent(t *testing.T) {
	m := NewWithBackend(&cloudInitProbeBackend{probeExitCode: 0}) // cloud-init present
	m.cloudInitWait = 50 * time.Millisecond                       // test seam, not the real 5s default

	start := time.Now()
	_ = m.installPackages("box-container", false, "", nil, "alice", ostype.Debian)
	elapsed := time.Since(start)

	if elapsed < m.cloudInitWait {
		t.Errorf("installPackages took %v — cloud-init present must still wait at least %v", elapsed, m.cloudInitWait)
	}
}
