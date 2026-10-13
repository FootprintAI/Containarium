package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/credentials"
	"github.com/footprintai/containarium/internal/sshkey"
)

func TestLogin_SSHKeyExpiryNudge(t *testing.T) {
	for _, tc := range []struct {
		name string
		days int
		warn bool
	}{
		{"seven days", 7, true},
		{"eight days", 8, false},
		{"already expired", -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSSHLoginHome(t)
			loginNoSSHSetup, loginNoBrowser = true, true
			expires := time.Now().UTC().Add(time.Duration(tc.days) * 24 * time.Hour).Format(time.RFC3339)
			var listed atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/cli/sessions":
					_ = json.NewEncoder(w).Encode(createSessionResp{SessionID: "expiry-test", UserCode: "TEST-1234", VerificationURL: "https://example.invalid/approve", ExpiresIn: 600})
				case "/v1/cli/sessions/expiry-test/status":
					_ = json.NewEncoder(w).Encode(sessionStatusResp{Status: "approved", Token: "expiry-token"})
				case "/v1/user/ssh-keys":
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer expiry-token" {
						t.Errorf("expected authenticated GET after login: %s, auth=%q", r.Method, r.Header.Get("Authorization"))
					}
					listed.Store(true)
					fmt.Fprintf(w, `{"keys":[{"name":"laptop","expires_at":%q}]}`, expires)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			loginServer = srv.URL
			old := loginPollIntervalForTest()
			t.Cleanup(func() { restorePollInterval(old) })
			setPollInterval(time.Millisecond)
			var out bytes.Buffer
			loginCmd.SetOut(&out)
			loginCmd.SetErr(&out)
			if err := runLogin(loginCmd, nil); err != nil {
				t.Fatal(err)
			}
			if !listed.Load() {
				t.Fatal("successful login did not check registered SSH keys")
			}
			if got := strings.Contains(out.String(), "containarium ssh rotate"); got != tc.warn {
				t.Fatalf("expiry reminder=%v, want %v:\n%s", got, tc.warn, out.String())
			}
		})
	}
}

func TestLogin_RetirementRespectsOtherServers(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		unavailable, retired, remove bool
	}{
		{"used on other server", false, false, false},
		{"other status unknown", true, false, false},
		{"retired on both servers", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := withSSHLoginHome(t)
			loginNoSSHSetup = true
			pubPath, pub, err := sshkey.GenerateFresh(sshkey.LocateOpts{HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			fp, err := sshkey.Fingerprint(pub)
			if err != nil {
				t.Fatal(err)
			}
			past := time.Now().Add(-time.Hour)
			f := newFakeLoginAndSSHKeysServer(t, 0)
			f.keys = []sshkey.SSHKey{{Name: "laptop", Fingerprint: fp, PublicKey: pub, RetiredAt: &past}}
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer other-token" {
					t.Error("other server did not receive its own credential")
				}
				if tc.unavailable {
					w.WriteHeader(503)
					return
				}
				key := sshkey.SSHKey{Fingerprint: fp, PublicKey: pub}
				if tc.retired {
					key.RetiredAt = &past
				}
				_ = json.NewEncoder(w).Encode(listSSHKeysResp{Keys: []sshkey.SSHKey{key}})
			}))
			defer other.Close()
			cf := credentials.NewCredentialsFile()
			cf.Set(other.URL, credentials.ServerCreds{Token: "other-token"})
			path, err := credentials.DefaultPath()
			if err != nil {
				t.Fatal(err)
			}
			if err := credentials.Save(path, cf); err != nil {
				t.Fatal(err)
			}
			// A per-invocation override must never be forwarded to other profiles.
			authToken = "current-server-override"
			if _, err := runLoginWithSSHFlagsHelper(t, f, ""); err != nil {
				t.Fatal(err)
			}
			_, err = os.Stat(strings.TrimSuffix(pubPath, ".pub"))
			if gone := os.IsNotExist(err); gone != tc.remove {
				t.Fatalf("key removed=%v, want %v", gone, tc.remove)
			}
		})
	}
}

func TestLogin_RotationHintPreservesLiteralArguments(t *testing.T) {
	withSSHLoginHome(t)
	loginNoSSHSetup = true
	f := newFakeLoginAndSSHKeysServer(t, 0)
	name := "laptop$(printf EXPANDED)"
	f.keys = []sshkey.SSHKey{{Name: name, ExpiresAt: time.Now().Add(time.Hour)}}
	out, err := runLoginWithSSHFlagsHelper(t, f, "")
	if err != nil {
		t.Fatal(err)
	}
	var hint string
	for _, line := range strings.Split(out.String(), "\n") {
		if _, command, ok := strings.Cut(line, "rotate it with "); ok {
			hint = command
		}
	}
	if hint == "" {
		t.Fatal("rotation hint missing")
	}
	// Execute the printed hint against a shell function that only records args.
	// Command substitution would change the name before the CLI validates it.
	got, err := exec.Command("sh", "-c", "containarium() { printf '%s\\n' \"$@\"; }\n"+hint).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), name+"\n") {
		t.Fatalf("shell expanded the key name: %s", got)
	}
}

func TestLogin_RemovesOnlyRetiredManagedKey(t *testing.T) {
	home := withSSHLoginHome(t)
	loginNoSSHSetup = true
	f := newFakeLoginAndSSHKeysServer(t, 0)
	past := time.Now().UTC().Add(-time.Hour)
	var paths []string
	for i := 0; i < 2; i++ {
		pubPath, pub, err := sshkey.GenerateFresh(sshkey.LocateOpts{HomeDir: home})
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, strings.TrimSuffix(pubPath, ".pub"))
		fp, err := sshkey.Fingerprint(pub)
		if err != nil {
			t.Fatal(err)
		}
		key := sshkey.SSHKey{Name: "laptop", PublicKey: pub, Fingerprint: fp, ExpiresAt: past}
		if i == 0 {
			key.RetiredAt = &past
		}
		f.keys = append(f.keys, key)
	}
	if _, err := runLoginWithSSHFlagsHelper(t, f, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths[0]); !os.IsNotExist(err) {
		t.Fatal("login did not remove explicitly retired key")
	}
	if _, err := os.Stat(paths[1]); err != nil {
		t.Fatal("login removed a merely expired key")
	}
}
