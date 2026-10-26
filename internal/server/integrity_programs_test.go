package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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

func TestComputeSelfMeasurement_ExecWatchOnlyWhenArmed(t *testing.T) {
	dir := t.TempDir()
	netObj := filepath.Join(dir, "netpolicy.bpf.o")
	for name, b := range map[string]string{netObj: "n", filepath.Join(dir, netbpf.ExecObjectName): "e"} {
		if err := os.WriteFile(name, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(appconfig.EnvNetworkPolicyBPFObject, netObj)
	names := func(armed bool) []string {
		s := &ContainerServer{}
		s.SetIntegrityExecWatch(armed)
		m, err := s.computeSelfMeasurement()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range m.ProgramDigests {
			out = append(out, p.Name)
		}
		return out
	}
	if got := names(false); len(got) != 1 || got[0] != netObj {
		t.Fatalf("unarmed: %v", got)
	}
	if got := names(true); len(got) != 2 {
		t.Fatalf("armed: %v", got)
	}
}
