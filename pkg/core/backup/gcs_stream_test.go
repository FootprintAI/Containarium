package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGcloudUploader_DownloadStream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake gcloud executable")
	}
	for _, tc := range []struct {
		name, script string
		limit        int64
		fail         bool
	}{
		{"success", "printf dump-data", 64, false},
		{"size-bound", "printf dump-data", 4, true},
		{"process-error", "printf partial; printf denied >&2; exit 1", 64, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := "#!/bin/sh\n[ \"$1\" = storage ] && [ \"$2\" = cat ] && [ \"$3\" = gs://backup-test/dump ] || exit 2\n" + tc.script + "\n"
			if err := os.WriteFile(filepath.Join(dir, "gcloud"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			g, err := NewGcloudUploader()
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			dst := &boundedWriter{w: &out, limit: tc.limit}
			err = g.DownloadStream("gs://backup-test/dump", dst)
			if (err != nil) != tc.fail {
				t.Fatalf("err=%v", err)
			}
			if int64(out.Len()) > tc.limit {
				t.Fatal("download exceeded writer bound")
			}
			if !tc.fail && out.String() != "dump-data" {
				t.Fatalf("download=%q", out.String())
			}
			if tc.name == "size-bound" && dst.err == nil {
				t.Fatal("size refusal lost")
			}
			if tc.name == "process-error" && !strings.Contains(err.Error(), "denied") {
				t.Fatalf("diagnostic lost: %v", err)
			}
		})
	}
}

func TestDownloadDiagnostic_IsBounded(t *testing.T) {
	d := &downloadDiagnostic{}
	p := bytes.Repeat([]byte("x"), 8192)
	for range 3 {
		n, err := d.Write(p)
		if err != nil || n != len(p) {
			t.Fatalf("diagnostic did not drain: %d %v", n, err)
		}
	}
	if d.Len() != 4096 {
		t.Fatalf("diagnostic size=%d", d.Len())
	}
}
