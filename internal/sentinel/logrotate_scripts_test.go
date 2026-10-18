//go:build !windows

package sentinel

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #2415 — both sentinel startup scripts must install a logrotate stanza for
// the SSH session sink, with a configurable retention, rotating in `create`
// mode (never copytruncate) and signalling ONLY the plugin to reopen.

const sinkPath = "/var/log/containarium/ssh-sessions.jsonl"

var sentinelScripts = []struct {
	name         string
	path         string
	retentionRef string // how `rotate <N>` references the configurable retention
	authzHUP     bool   // the unit can run ssh-authz-plugin in enforce mode
}{
	{"module", "../../terraform/modules/containarium/scripts/startup-sentinel.sh", "${ssh_session_log_retention_days}", true},
	{"gce", "../../terraform/gce/scripts/startup-sentinel.sh", "$SSH_SESSION_LOG_RETENTION_DAYS", false},
}

func stanzaOf(t *testing.T, script string) string {
	t.Helper()
	b, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, sinkPath+" {")
	if i < 0 {
		t.Fatalf("%s has no logrotate stanza for %s", script, sinkPath)
	}
	j := strings.Index(src[i:], "\n}")
	if j < 0 {
		t.Fatalf("%s: unterminated logrotate stanza", script)
	}
	return src[i : i+j+2]
}

func TestSentinelScripts_LogrotateStanza(t *testing.T) {
	for _, sc := range sentinelScripts {
		t.Run(sc.name, func(t *testing.T) {
			st := stanzaOf(t, sc.path)
			for _, want := range []string{
				"daily", "compress", "delaycompress", "missingok", "notifempty",
				"create 0600 root root",
				"rotate " + sc.retentionRef,
				"postrotate", "endscript",
				// Anchored: sshpiperd's own command line CONTAINS the plugin's,
				// and it must not receive the SIGHUP.
				"pkill -HUP -f '" + sessionReopenPattern + "'",
			} {
				if !strings.Contains(st, want) {
					t.Errorf("stanza missing %q:\n%s", want, st)
				}
			}
			// An enforce-mode ssh-authz-plugin appends denials to the sink
			// (#2520). Only that one is signalled: a pre-enforce plugin
			// exits on SIGHUP and takes sshpiperd down with it.
			authzHUP := "pkill -HUP -f '" + authzReopenPattern + "'"
			if got := strings.Contains(st, authzHUP); got != sc.authzHUP {
				t.Errorf("stanza contains %q = %v, want %v:\n%s", authzHUP, got, sc.authzHUP, st)
			}
			if n := strings.Count(st, "pkill"); n != map[bool]int{false: 1, true: 2}[sc.authzHUP] {
				t.Errorf("stanza has %d pkill lines; an unexpected one may signal a plugin that exits on SIGHUP:\n%s", n, st)
			}
			if strings.Contains(st, "copytruncate") {
				t.Errorf("copytruncate loses records written between copy and truncate and breaks the shipper's inode tracking:\n%s", st)
			}
		})
	}
}

const (
	sessionReopenPattern = "^/usr/local/bin/containariumd? sentinel ssh-session-plugin"
	authzReopenPattern   = "^/usr/local/bin/containariumd? sentinel ssh-authz-plugin .*--ssh-authz-enforce"
)

func TestSentinelScripts_ReopenPatternsTargetOnlyTheSinkWriters(t *testing.T) {
	session := regexp.MustCompile(sessionReopenPattern)
	authz := regexp.MustCompile(authzReopenPattern)
	for cmdline, want := range map[string]struct{ session, authz bool }{
		"/usr/local/bin/containariumd sentinel ssh-session-plugin --records-file " + sinkPath:                                            {true, false},
		"/usr/local/bin/containariumd sentinel ssh-authz-plugin --ssh-authz-grace 5m --ssh-authz-enforce --records-file " + sinkPath:     {false, true},
		"/usr/local/bin/containariumd sentinel ssh-authz-plugin --ssh-authz-socket /run/containarium/sentinel.sock --ssh-authz-grace 5m": {false, false},
		"/usr/local/bin/sshpiperd -i /etc/sshpiper/host_key /usr/local/bin/containariumd sentinel ssh-authz-plugin --ssh-authz-enforce":  {false, false},
		"/usr/local/bin/containariumd sentinel ssh-ban-plugin --listener main":                                                           {false, false},
	} {
		if got := session.MatchString(cmdline); got != want.session {
			t.Errorf("session pattern on %q = %v, want %v", cmdline, got, want.session)
		}
		if got := authz.MatchString(cmdline); got != want.authz {
			t.Errorf("authz pattern on %q = %v, want %v", cmdline, got, want.authz)
		}
	}
}

func TestSentinelScripts_RetentionIsConfigurableWithA90DayDefault(t *testing.T) {
	vars, err := os.ReadFile("../../terraform/modules/containarium/variables.tf")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)variable "ssh_session_log_retention_days" \{.*?default\s*=\s*(\d+)`).FindStringSubmatch(string(vars))
	if m == nil || m[1] != "90" {
		t.Fatalf("module variable ssh_session_log_retention_days must exist with default 90, got %v", m)
	}
	tf, _ := os.ReadFile("../../terraform/modules/containarium/sentinel.tf")
	if !strings.Contains(string(tf), "ssh_session_log_retention_days = var.ssh_session_log_retention_days") {
		t.Error("sentinel.tf must pass the retention into the startup-script template")
	}
	gce, _ := os.ReadFile("../../terraform/gce/scripts/startup-sentinel.sh")
	if !regexp.MustCompile(`SSH_SESSION_LOG_RETENTION_DAYS=.*\b90\b`).Match(gce) {
		t.Error("the gce script must default the retention to 90 days")
	}
}

// If logrotate is installed, its own parser must accept each stanza.
func TestSentinelScripts_LogrotateAcceptsTheStanza(t *testing.T) {
	bin, err := exec.LookPath("logrotate")
	if err != nil {
		t.Skip("logrotate not installed")
	}
	for _, sc := range sentinelScripts {
		t.Run(sc.name, func(t *testing.T) {
			dir := t.TempDir()
			st := strings.ReplaceAll(stanzaOf(t, sc.path), sc.retentionRef, "90")
			st = strings.ReplaceAll(st, sinkPath, filepath.Join(dir, "ssh-sessions.jsonl"))
			conf := filepath.Join(dir, "conf")
			if err := os.WriteFile(conf, []byte(st+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(dir, "ssh-sessions.jsonl"), []byte("x\n"), 0o600)
			out, err := exec.Command(bin, "-d", "-s", filepath.Join(dir, "state"), conf).CombinedOutput()
			if err != nil {
				t.Fatalf("logrotate rejected the stanza: %v\n%s", err, out)
			}
		})
	}
}
