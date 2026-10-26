package server

import (
	"os"
	"path/filepath"
	"testing"
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
