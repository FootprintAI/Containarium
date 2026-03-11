package security

import "testing"

func TestParseClamScanOutput(t *testing.T) {
	tests := []struct {
		name           string
		output         string
		wantStatus     string
		wantCount      int
		wantFindings   string
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
			name:       "infected output",
			output:     "/mnt/scan/home/user/eicar.com: Eicar-Signature FOUND\n/mnt/scan/tmp/malware.exe: Win.Trojan.Agent FOUND\n",
			wantStatus: "infected",
			wantCount:  2,
			wantFindings: "/mnt/scan/home/user/eicar.com: Eicar-Signature FOUND\n/mnt/scan/tmp/malware.exe: Win.Trojan.Agent FOUND",
		},
		{
			name:       "mixed output with one finding",
			output:     "/mnt/scan/usr/bin/ls: OK\n/mnt/scan/home/user/eicar.com: Eicar-Signature FOUND\n/mnt/scan/usr/bin/cat: OK\n",
			wantStatus: "infected",
			wantCount:  1,
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
