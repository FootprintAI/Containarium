package coderun

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"strings"
	"testing"
	"time"
)

func TestBootstrapReportScript_IsTheSharedScriptPlusTheManifestTrailer(t *testing.T) {
	const url = "https://bundles.example.com/b/x"
	base, report := BootstrapScript(url), BootstrapReportScript(url)
	if !strings.HasPrefix(report, base) {
		t.Fatal("the daemon's script does not start with the exact script code install runs")
	}
	if !strings.Contains(report[len(base):], BootstrapManifestMarker) {
		t.Error("no manifest marker after the apply step")
	}
}

func TestParseBootstrapReport(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		rev     int32
		found   bool
		wantErr bool
	}{
		{"manifest after apply output", "applied\n\n" + BootstrapManifestMarker + "\n{\"bundle_revision\": 9, \"skills\": []}\n", 9, true, false},
		{"apply output that mimics the marker earlier", BootstrapManifestMarker + "\n{\"bundle_revision\":1}\n\n" + BootstrapManifestMarker + "\n{\"bundle_revision\":2}", 2, true, false},
		{"no manifest in the bundle", "applied\n\n" + BootstrapManifestMarker + "\n", 0, false, false},
		{"manifest without the field", BootstrapManifestMarker + "\n{}\n", 0, true, false},
		{"no marker", "applied\n", 0, false, false},
		{"manifest not JSON", BootstrapManifestMarker + "\nnot json\n", 0, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rev, found, err := ParseBootstrapReport(tc.out)
			if (err != nil) != tc.wantErr || rev != tc.rev || found != tc.found {
				t.Errorf("= %d, %v, %v; want %d, %v, err=%v", rev, found, err, tc.rev, tc.found, tc.wantErr)
			}
		})
	}
}

// A bundle server that answers and then stops sending is cut off by the stall
// bound and reported as a fetch that reached the server (exit 6), instead of
// holding the box (and the daemon's per-box apply) until the exec times out.
func TestBootstrapScript_StalledServerIsCutOffAsFetchReached(t *testing.T) {
	for _, tool := range []string{"sh", "curl", "tar"} {
		if _, err := osexec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	orig := BootstrapStallSeconds
	BootstrapStallSeconds = 1
	t.Cleanup(func() { BootstrapStallSeconds = orig })

	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(stop); srv.Close() })

	cmd := osexec.Command("sh", "-c", BootstrapScript(srv.URL+"/b.tgz"))
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	start := time.Now()
	err := cmd.Run()
	var ee *osexec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != BootstrapExitFetchReached {
		t.Fatalf("err = %v, want exit %d", err, BootstrapExitFetchReached)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("a stalled fetch took %s to be cut off", took)
	}
}

func TestBootstrapScript_FetchIsStallBoundedNotSizeBounded(t *testing.T) {
	s := BootstrapScript("https://bundles.example.com/b.tgz")
	for _, want := range []string{"--connect-timeout ", "--speed-limit 1 --speed-time "} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "--max-time") || strings.Contains(s, " -m ") {
		t.Error("a fixed total time limit would cut off a large bundle on a slow link")
	}
}
