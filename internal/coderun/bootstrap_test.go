package coderun

import (
	"strings"
	"testing"
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
