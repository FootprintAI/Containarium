package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testClaimToken = "v1.anon-1a2b3c4d-container.ff00.1790870400.0123456789abcdef0123456789abcdef.aa"

func TestRenderClaim(t *testing.T) {
	tests := []struct {
		name    string
		content string
		json    bool
		want    []string
		wantErr bool
	}{
		{"url", "https://cloud.example.test/claim?token=" + testClaimToken, false,
			[]string{"open this link", "https://cloud.example.test/claim?token=" + testClaimToken, "expires with the box at 2026-10-01T16:00:00Z"}, false},
		{"bare token", testClaimToken, false,
			[]string{"no claim URL configured", testClaimToken, "containarium anon claim", "2026-10-01T16:00:00Z"}, false},
		{"url json", "https://cloud.example.test/claim?token=" + testClaimToken, true,
			[]string{`"url": "https://cloud.example.test/claim?token=` + testClaimToken + `"`, `"token": "` + testClaimToken + `"`, `"expires_at": "2026-10-01T16:00:00Z"`}, false},
		{"empty", "   ", false, nil, true},
		{"not a token", "https://x/claim?token=hello", false, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := renderClaim(tt.content, tt.json)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
			if tt.json && err == nil {
				var info claimInfo
				if json.Unmarshal([]byte(out), &info) != nil || info.Token != testClaimToken {
					t.Errorf("not valid JSON with the token: %s", out)
				}
			}
		})
	}
}

func TestClaimCmd_NotAnAnonymousBox(t *testing.T) {
	old := claimURLFile
	claimURLFile = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { claimURLFile = old })

	err := claimCmd.RunE(claimCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "not an anonymous box") {
		t.Errorf("err = %v", err)
	}
}

func TestClaimCmd_PrintsFile(t *testing.T) {
	old := claimURLFile
	claimURLFile = filepath.Join(t.TempDir(), "claim-url")
	t.Cleanup(func() { claimURLFile = old })
	if err := os.WriteFile(claimURLFile, []byte(testClaimToken+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	claimCmd.SetOut(&sb)
	if err := claimCmd.RunE(claimCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), testClaimToken) {
		t.Errorf("output = %s", sb.String())
	}
}
