package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialAlertStatusScript(t *testing.T) {
	const now = int64(1800000000)
	script, ok := CredentialAlertStatusScript(NameClaude)
	if !ok {
		t.Fatal("missing Claude alert probe")
	}
	for _, tc := range []struct {
		name                            string
		expires                         int64
		missingExpiry, noSignIn, failed bool
		want                            CredentialStatusSource
	}{
		{name: "recent expiry refreshable", expires: now - 60, want: CredentialStatusInteractive},
		{name: "exactly 24 hours", expires: now - 86400, want: CredentialStatusInteractive},
		{name: "over 24 hours", expires: now - 86401, want: CredentialStatusExpired},
		{name: "future expiry", expires: now + 60, want: CredentialStatusInteractive},
		{name: "unknown expiry", missingExpiry: true, want: CredentialStatusInteractive},
		{name: "authentication failure despite future expiry", expires: now + 60, failed: true, want: CredentialStatusInteractive},
		{name: "authentication failure during recent expiry", expires: now - 60, failed: true, want: CredentialStatusInteractive},
		{name: "API key ignores stale failure", noSignIn: true, failed: true, want: CredentialStatusAPIKey},
	} {
		for _, millis := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ms=%v", tc.name, millis), func(t *testing.T) {
				home := t.TempDir()
				mustMkdirAll(t, filepath.Join(home, ".claude"))
				mustWriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"env":{"ANTHROPIC_API_KEY":"FAKE_SECRET_NEVER_OUTPUT"}}`)
				if !tc.noSignIn {
					exp := tc.expires
					if millis {
						exp *= 1000
					}
					content := fmt.Sprintf(`{"accessToken":"FAKE_ACCESS_NEVER_OUTPUT","refreshToken":"FAKE_REFRESH_NEVER_OUTPUT","expiresAt":%d}`, exp)
					if tc.missingExpiry {
						content = `{"refreshToken":"FAKE_REFRESH_NEVER_OUTPUT"}`
					}
					mustWriteFile(t, filepath.Join(home, ".claude", ".credentials.json"), content)
				}
				if tc.failed {
					dir := filepath.Join(home, ".local", "state", "containarium")
					mustMkdirAll(t, dir)
					mustWriteFile(t, filepath.Join(dir, "claude-auth-failed"), "")
				}
				bin := filepath.Join(home, "bin")
				mustMkdirAll(t, bin)
				if err := os.WriteFile(filepath.Join(bin, "date"), []byte(fmt.Sprintf("#!/bin/sh\necho %d\n", now)), 0700); err != nil {
					t.Fatal(err)
				}
				got := runCredentialStatusScript(t, script, home, []string{"PATH=" + bin + ":" + os.Getenv("PATH")})
				if got != string(tc.want) {
					t.Fatalf("source=%q want=%q", got, tc.want)
				}
			})
		}
	}
}

func TestCredentialAlertStatusScriptOtherEnginesUnchanged(t *testing.T) {
	for _, n := range []Name{NamePi, NameCodex, Name("unsupported")} {
		raw, rawOK := CredentialStatusScript(n)
		alert, alertOK := CredentialAlertStatusScript(n)
		if raw != alert || rawOK != alertOK {
			t.Fatalf("changed non-Claude probe: %s", n)
		}
	}
}
