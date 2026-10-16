package security

import (
	"errors"
	"strings"
	"testing"
)

func TestParseClamScanOutput(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		wantStatus   string
		wantCount    int
		wantFindings string
	}{
		{
			name:       "clean output",
			output:     "/mnt/scan/usr/bin/ls: OK\n/mnt/scan/usr/bin/cat: OK\n",
			wantStatus: "clean",
			wantCount:  0,
		},
		{
			name:       "empty output",
			output:     "",
			wantStatus: "clean",
			wantCount:  0,
		},
		{
			name:         "infected output",
			output:       "/mnt/scan/home/user/eicar.com: Eicar-Signature FOUND\n/mnt/scan/tmp/malware.exe: Win.Trojan.Agent FOUND\n",
			wantStatus:   "infected",
			wantCount:    2,
			wantFindings: "/mnt/scan/home/user/eicar.com: Eicar-Signature FOUND\n/mnt/scan/tmp/malware.exe: Win.Trojan.Agent FOUND",
		},
		{
			name:         "mixed output with one finding",
			output:       "/mnt/scan/usr/bin/ls: OK\n/mnt/scan/home/user/eicar.com: Eicar-Signature FOUND\n/mnt/scan/usr/bin/cat: OK\n",
			wantStatus:   "infected",
			wantCount:    1,
			wantFindings: "/mnt/scan/home/user/eicar.com: Eicar-Signature FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, count, findings := ParseClamScanOutput(tt.output)
			if status != tt.wantStatus {
				t.Errorf("status = %q, want %q", status, tt.wantStatus)
			}
			if count != tt.wantCount {
				t.Errorf("count = %d, want %d", count, tt.wantCount)
			}
			if tt.wantFindings != "" && findings != tt.wantFindings {
				t.Errorf("findings = %q, want %q", findings, tt.wantFindings)
			}
		})
	}
}

func TestClassifyClamScan(t *testing.T) {
	exit1 := errors.New("command exited with code 1")
	exit2 := errors.New("command exited with code 2")
	found := "/mnt/scan-x/a: Eicar-Test-Signature FOUND\n"
	tests := []struct {
		name       string
		stdout     string
		stderr     string
		err        error
		wantStatus string
		wantCount  int
	}{
		{"exit 0, no findings", "", "", nil, ScanStatusClean, 0},
		{"exit 1 with FOUND", found, "", exit1, ScanStatusInfected, 1},
		{"exit 2 with FOUND still infected", found, "WARNING: x", exit2, ScanStatusInfected, 1},
		{"exit 2, no FOUND is not clean", "", "ERROR: Can't access file", exit2, ScanStatusIncomplete, 0},
		{"exit 1 without FOUND is not clean", "", "", exit1, ScanStatusIncomplete, 0},
		{"exec failure is not clean", "", "", errors.New("failed to execute command"), ScanStatusIncomplete, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, count, findings := ClassifyClamScan(tt.stdout, tt.stderr, tt.err)
			if status != tt.wantStatus || count != tt.wantCount {
				t.Fatalf("got (%q, %d), want (%q, %d)", status, count, tt.wantStatus, tt.wantCount)
			}
			if tt.err != nil && !strings.Contains(findings, tt.err.Error()) {
				t.Errorf("incomplete findings %q should carry the exec error", findings)
			}
		})
	}
}
