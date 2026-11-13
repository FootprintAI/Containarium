package threatdetect

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func newTestAbuseToolRule(t *testing.T) *AbuseToolRule {
	t.Helper()
	r, err := NewAbuseToolRule()
	if err != nil {
		t.Fatalf("NewAbuseToolRule: %v", err)
	}
	return r
}

// The embedded list must parse and hold entries; a malformed one fails the
// build here rather than at daemon start.
func TestAbuseToolBaselineParses(t *testing.T) {
	version, entries, err := parseBaselineMinerSigYAML(embeddedToolSigYAML)
	if err != nil {
		t.Fatalf("baseline does not parse: %v", err)
	}
	if version == "" || len(entries) < 10 {
		t.Fatalf("baseline version %q with %d entries", version, len(entries))
	}
	for _, e := range entries {
		if e.Kind == pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256 {
			t.Errorf("the baseline must hold no hash entries (it would go stale): %+v", e)
		}
		if !e.Builtin {
			t.Errorf("a baseline entry must be marked builtin: %+v", e)
		}
	}
	if r := newTestAbuseToolRule(t); r.BaselineVersion() != version {
		t.Errorf("BaselineVersion = %q, want %q", r.BaselineVersion(), version)
	}
}

func TestAbuseToolRule_Matches(t *testing.T) {
	r := newTestAbuseToolRule(t)
	for _, tc := range []struct {
		name        string
		ev          ExecEvent
		wantSubject string
	}{
		{"frp client", execEv("/usr/local/bin/frpc", "frpc", "/usr/local/bin/frpc -c /etc/frp/frpc.toml"), "name:frpc"},
		{"frp server", execEv("/opt/frps", "frps", "./frps"), "name:frps"},
		{"chisel", execEv("/tmp/chisel", "chisel", "./chisel client h:8080 R:2222:127.0.0.1:22"), "name:chisel"},
		{"renamed path, comm gives it away", execEv("/usr/bin/.cache", "frpc", "/usr/bin/.cache"), "name:frpc"},
		{"slowloris binary", execEv("/opt/slowloris", "slowloris", "./slowloris target"), "name:slowloris"},
		{"script run directly (shebang)", execEv("/opt/tools/hulk.py", "hulk.py", "./hulk.py http://x"), "name:hulk.py"},
		{"script by absolute path", execEv("/usr/bin/python3", "python3", "python3 /root/tools/slowloris.py example.com"), "name:slowloris.py"},
		{"script in cwd", execEv("/usr/bin/python3", "python3", "python3 hulk.py http://example.com"), "name:hulk.py"},
		{"after an option", execEv("/usr/bin/python3.12", "python3", "python3 -u -B /opt/GoldenEye/goldeneye.py http://x"), "name:goldeneye.py"},
		{"glob script name", execEv("/usr/bin/python3", "python3", "python3 /opt/x/mhddos_proxy.py GET http://x"), "name:mhddos*.py"},
		{"proxy-rotating tool from an incident, in its directory", execEv("/usr/bin/python3.12", "python3", "python3 blankdisk.py"), "name:blankdisk*.py"},
		{"proxy-rotating tool by path", execEv("/usr/bin/python3.12", "python3", "python3 /root/BLANKDISK_v5.5-ddos-tool/blankdisk.py"), "name:blankdisk*.py"},
		{"perl and node interpreters", execEv("/usr/bin/node", "node", "node /srv/torshammer.py"), "name:torshammer.py"},
		{"case-insensitive", execEv("/usr/bin/python3", "python3", "python3 /opt/HULK.PY"), "name:hulk.py"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := r.OnExec(RuleContext{}, tc.ev)
			if len(got) != 1 || got[0].Subject != "container:box-1:"+tc.wantSubject {
				t.Fatalf("findings = %+v, want one with subject container:box-1:%s", got, tc.wantSubject)
			}
			f := got[0]
			if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM || f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_ABUSE_TOOL ||
				f.Container != "box-1" || f.TenantID != "t1" {
				t.Fatalf("finding = %+v", f)
			}
			if len(f.Evidence.Execs) != 1 || f.Evidence.Execs[0].Matched != tc.wantSubject || f.Evidence.Execs[0].PID != 4242 {
				t.Fatalf("evidence = %+v", f.Evidence)
			}
		})
	}
}

// Ordinary work that merely mentions a tool must not match: reading or editing
// a file with a tool's name is not running it, and a commit message is one
// argument, not a script.
func TestAbuseToolRule_NoFalsePositives(t *testing.T) {
	r := newTestAbuseToolRule(t)
	for name, ev := range map[string]ExecEvent{
		"reading a tunnel config":         execEv("/bin/cat", "cat", "cat /etc/frp/frpc.toml"),
		"reading a tool's script":         execEv("/bin/cat", "cat", "cat /opt/tools/hulk.py"),
		"editing a tool's script":         execEv("/usr/bin/vim", "vim", "vim hulk.py"),
		"installing a tunnel client":      execEv("/usr/bin/apt", "apt", "apt install frp"),
		"grep for a tool name":            execEv("/bin/grep", "grep", "grep -r slowloris docs/"),
		"git add of such a file":          execEv("/usr/bin/git", "git", "git add hulk.py"),
		"git commit mentioning a tool":    execArgs("/usr/bin/git", "git", "git", "commit", "-m", "add hulk.py support"),
		"cloudflared (platform ingress)":  execEv("/usr/bin/cloudflared", "cloudflared", "cloudflared tunnel run"),
		"ssh port forward":                execEv("/usr/bin/ssh", "ssh", "ssh -L 8080:localhost:80 host"),
		"plain python":                    execEv("/usr/bin/python3", "python3", "python3 manage.py runserver"),
		"python module":                   execEv("/usr/bin/python3", "python3", "python3 -m http.server 8000"),
		"python with no script":           execEv("/usr/bin/python3", "python3", "python3"),
		"python script named like a word": execEv("/usr/bin/python3", "python3", "python3 chiseled.py"),
		"empty":                           {Container: "box-1"},
	} {
		if got := r.OnExec(RuleContext{}, ev); len(got) != 0 {
			t.Errorf("%s: finding %+v, want none", name, got)
		}
	}
}

// Record-only by construction: the responder never acts on it, and it never
// kills a process, whatever policy is set.
func TestAbuseToolRule_IsRecordOnly(t *testing.T) {
	if RespondsTo(pb.ThreatRuleId_THREAT_RULE_ID_ABUSE_TOOL) {
		t.Fatal("abuse-tool findings must never reach the process responder")
	}
	if KillsProcess(pb.ThreatRuleId_THREAT_RULE_ID_ABUSE_TOOL) {
		t.Fatal("abuse-tool findings must never kill a process")
	}
}

// The engine delivers execs to rules that implement ExecConsumer.
func TestAbuseToolRule_IsAnExecConsumer(t *testing.T) {
	var _ ExecConsumer = (*AbuseToolRule)(nil)
	var _ Rule = (*AbuseToolRule)(nil)
}
