package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appconfig "github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/integrity"
	"github.com/footprintai/containarium/internal/netbpf"
)

func TestIntegrityProgramObjects(t *testing.T) {
	blob := []byte("embedded-object")
	dir := t.TempDir()
	obj := filepath.Join(dir, "netpolicy.bpf.o")
	if err := os.WriteFile(obj, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("unset yields none", func(t *testing.T) {
		got, err := integrityProgramObjects("  ", blob)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("path keeps path semantics", func(t *testing.T) {
		got, err := integrityProgramObjects(obj, blob)
		if err != nil || len(got) != 1 || got[0].Name != obj || got[0].Path != obj || got[0].Data != nil {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	for _, v := range []string{"embedded", "1", "true", "yes", "YES", "Embedded", "TRUE", " ON "} {
		t.Run("embedded "+v, func(t *testing.T) {
			got, err := integrityProgramObjects(v, blob)
			if err != nil || len(got) != 1 {
				t.Fatalf("got %+v, %v", got, err)
			}
			if got[0].Name != "embedded" || got[0].Path != "" || string(got[0].Data) != string(blob) {
				t.Fatalf("got %+v, want stable name \"embedded\" carrying the embedded bytes", got[0])
			}
		})
	}
	t.Run("embedded without a bundled object errors clearly", func(t *testing.T) {
		if _, err := integrityProgramObjects("embedded", nil); err == nil {
			t.Fatal("want error when the build has no embedded object")
		}
	})
}

func digestOf(t *testing.T, progs []integrity.ProgramObject) []integrity.ProgramDigest {
	t.Helper()
	m, err := integrity.Compute(integrity.Inputs{Programs: progs, Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return m.ProgramDigests
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestIntegrityExecWatchObjects(t *testing.T) {
	blob := []byte("embedded-exec-object")
	dir := t.TempDir()
	netObj := filepath.Join(dir, "netpolicy.bpf.o")
	sibling := filepath.Join(dir, netbpf.ExecObjectName)
	siblingBytes := []byte("sibling-exec-object")
	if err := os.WriteFile(sibling, siblingBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("empty setting yields none, matching the netpolicy measurement", func(t *testing.T) {
		for _, v := range []string{"", "  "} {
			got, err := integrityExecWatchObjects(v, blob)
			if err != nil || len(got) != 0 {
				t.Fatalf("exec %q: got %+v, %v", v, got, err)
			}
			net, _ := integrityProgramObjects(v, blob)
			if len(net) != 0 {
				t.Fatalf("netpolicy %q: got %+v", v, net)
			}
		}
	})
	for _, v := range []string{"embedded", "1", "true", "yes", "YES", " ON "} {
		t.Run("embedded "+v, func(t *testing.T) {
			got, err := integrityExecWatchObjects(v, blob)
			if err != nil || len(got) != 1 {
				t.Fatalf("got %+v, %v", got, err)
			}
			if got[0].Name != "execwatch-embedded" || got[0].Path != "" {
				t.Fatalf("got %+v", got[0])
			}
			d := digestOf(t, got)
			if len(d) != 1 || d[0].Digest != sha(blob) {
				t.Fatalf("digest %+v, want sha256 of the bytes handed to the loader", d)
			}
		})
	}
	t.Run("embedded without bundled exec object is skipped (never loaded)", func(t *testing.T) {
		got, err := integrityExecWatchObjects("embedded", nil)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("path digests the sibling file the loader reads", func(t *testing.T) {
		got, err := integrityExecWatchObjects(netObj, nil)
		if err != nil || len(got) != 1 {
			t.Fatalf("got %+v, %v", got, err)
		}
		_, loaderPath := netbpf.ExecObjectSource(netObj)
		if got[0].Name != sibling || got[0].Path != loaderPath || loaderPath != sibling {
			t.Fatalf("got %+v, loader path %q", got[0], loaderPath)
		}
		d := digestOf(t, got)
		if len(d) != 1 || d[0].Digest != sha(siblingBytes) {
			t.Fatalf("digest %+v", d)
		}
	})
	t.Run("missing sibling is skipped (the watcher is unavailable)", func(t *testing.T) {
		got, err := integrityExecWatchObjects(filepath.Join(t.TempDir(), "netpolicy.bpf.o"), nil)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
}

func TestComputeSelfMeasurement_ExecWatchOnlyWhenLoaded(t *testing.T) {
	dir := t.TempDir()
	netObj := filepath.Join(dir, "netpolicy.bpf.o")
	for name, b := range map[string]string{netObj: "n", filepath.Join(dir, netbpf.ExecObjectName): "e"} {
		if err := os.WriteFile(name, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(appconfig.EnvNetworkPolicyBPFObject, netObj)
	count := func(probe func() bool) int {
		s := &ContainerServer{}
		if probe != nil {
			s.SetIntegrityExecWatch(probe)
		}
		m, err := s.computeSelfMeasurement()
		if err != nil {
			t.Fatal(err)
		}
		return len(m.ProgramDigests)
	}
	// Real watchers: constructed-but-never-started (enforcer nil, or load
	// failed) reports not running; a started one is running.
	unavailable := NewExecWatcher(nil)
	unavailable.setStatus(execTelemetryUnavailable(errors.New("no BTF")))
	loaded := NewExecWatcher(nil)
	loaded.setStatus(execTelemetryOK)

	cases := []struct {
		name  string
		probe func() bool
		want  int
	}{
		{"no watcher wired", nil, 1},
		{"constructed, never started (enforcer nil)", NewExecWatcher(nil).Running, 1},
		{"constructed but unavailable", unavailable.Running, 1},
		{"loaded", loaded.Running, 2},
	}
	for _, c := range cases {
		if got := count(c.probe); got != c.want {
			t.Errorf("%s: %d program digests, want %d", c.name, got, c.want)
		}
	}
	// Live: the same server follows the watcher's status between heartbeats.
	w := NewExecWatcher(nil)
	s := &ContainerServer{}
	s.SetIntegrityExecWatch(w.Running)
	w.setStatus(execTelemetryOK)
	m, _ := s.computeSelfMeasurement()
	w.setStatus(execTelemetryUnavailable(errors.New("ring consumer exited")))
	m2, _ := s.computeSelfMeasurement()
	if len(m.ProgramDigests) != 2 || len(m2.ProgramDigests) != 1 {
		t.Errorf("live probe: %d then %d", len(m.ProgramDigests), len(m2.ProgramDigests))
	}
}

// The wiring line in NewDualServer connects the constructed watcher to the
// measurement; deleting it must fail a test (the line lives in a function too
// large to construct in a unit test).
func TestDualServerWiresExecWatcherIntoMeasurement(t *testing.T) {
	src, err := os.ReadFile("dual_server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "containerServer.SetIntegrityExecWatch(execWatcher.Running)") {
		t.Fatal("NewDualServer no longer wires execWatcher.Running into the integrity self-measurement (#3120)")
	}
}
