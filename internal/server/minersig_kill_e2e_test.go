//go:build incus

// Real-kernel, real-Incus coverage for the miner-signature rule and the
// kill_process path (#2638): a stub named `xmrig` run with
// `--donate-level 1` inside a box raises a HIGH MINER_SIGNATURE finding with
// the exec attached, is SIGKILLed from the host (kill_process=true) and the
// kill is audited with its pid; the same stub named `gcc` raises nothing
// from this rule. Needs root on an Incus host with kernel BTF, the execwatch
// object, and a running box to exec in:
//
//	sudo CONTAINARIUM_E2E_INCUS_CONTAINER=<name> \
//	  CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=<path to netpolicy.bpf.o | embedded> \
//	  go test -tags=incus -run TestMinerSignatureE2E ./internal/server/
//
// Skips (does not fail) without them. CI has no such host; the sprint's
// verification pass runs it (the issue's Verify-on-dev steps).
package server

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// minerStub busy-loops, so the `gcc` copy has the same CPU profile as the
// `xmrig` one; only the name and argv differ.
const minerStub = "#!/bin/sh\nwhile :; do :; done\n"

func TestMinerSignatureE2E_FindingKillAndAudit(t *testing.T) {
	name := os.Getenv("CONTAINARIUM_E2E_INCUS_CONTAINER")
	if name == "" {
		t.Skip("CONTAINARIUM_E2E_INCUS_CONTAINER is unset; needs a running Incus box to exec in")
	}
	obj := os.Getenv("CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT")
	if obj == "" {
		t.Skip("CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT is unset; needs the execwatch object")
	}
	client, err := incus.New()
	if err != nil {
		t.Skipf("no Incus here: %v", err)
	}
	initPID, err := client.InitPID(name)
	if err != nil || initPID <= 0 {
		t.Fatalf("InitPID(%s) = %d, %v; want a running box", name, initPID, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Responder with the real host killer; kill_process on, policy ALERT so
	// the box itself is left alone.
	findings := newFakeFindings()
	policies := threatdetect.NewProcessPolicyStore(nil)
	if err := policies.SetDefault(ctx, &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, KillProcess: proto.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	auditLog := &fakeAudit{}
	responder := NewProcessResponder(policies, threatdetect.NewMemActionStore(), findings, incusActuator{c: client}, auditLog, false)
	responder.SetProcessKiller(newHostProcessKiller(client.InitPID))
	go responder.Run(ctx) // the async sink's worker, as in production

	engine := threatdetect.NewEngine(NewAsyncActingSink(findings, responder), "e2e", false, nil, nil)
	rule, err := threatdetect.NewMinerSignatureRule(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Register(rule)

	// Every file goes in through the Incus file API, and each stub is
	// started by a launcher script run with no arguments, so no exec but the
	// stub itself ever carries a marker in its argv: a wrapper `sh -c "...
	// --donate-level 1"` would match (and be killed) first.
	write := func(path, content string) {
		t.Helper()
		if err := client.WriteFile(name, path, []byte(content), "0755"); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	launcher := func(cmdline string) string {
		// HUP ignored so the stub outlives the exec session; the
		// disposition survives the stub's exec.
		return "#!/bin/sh\ntrap '' HUP\n" + cmdline + " >/dev/null 2>&1 &\n"
	}
	write("/tmp/xmrig", minerStub)
	write("/tmp/gcc", minerStub)
	write("/tmp/worker", minerStub)
	write("/tmp/launch-a", launcher("/tmp/xmrig --donate-level 1"))
	write("/tmp/launch-b", launcher("/tmp/gcc -O2"))
	write("/tmp/launch-c", launcher("/tmp/worker -o stratum+tcp://pool.invalid:3333"))
	t.Cleanup(func() {
		_, _, _ = client.ExecWithOutput(name, []string{"sh", "-c", "pkill -f /tmp/gcc; rm -f /tmp/xmrig /tmp/gcc /tmp/worker /tmp/launch-a /tmp/launch-b /tmp/launch-c"})
	})
	run := func(path string) {
		t.Helper()
		if _, stderr, err := client.ExecWithOutput(name, []string{path}); err != nil {
			t.Fatalf("exec %s: %v (%s)", path, err, stderr)
		}
	}

	watcher := NewExecWatcher(engine.OnExec)
	if err := watcher.Start(ctx, obj); err != nil {
		t.Skipf("exec telemetry unavailable here: %v", err)
	}
	defer watcher.Stop()
	watcher.Reconcile([]incus.ContainerInfo{{Name: name, State: "Running", Pid: initPID, Tenant: "e2e"}})

	sigFindings := func() []*threatdetect.Finding {
		return findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE)
	}
	// killedPIDFor returns the pid of the audited kill of filename, 0 if none.
	killedPIDFor := func(filename string) uint32 {
		for _, d := range auditDetails(auditLog, "kill") {
			if !strings.Contains(d, "filename="+strconv.Quote(filename)) {
				continue
			}
			for _, f := range strings.Fields(d) {
				if v, ok := strings.CutPrefix(f, "pid="); ok {
					if n, err := strconv.ParseUint(v, 10, 32); err == nil {
						return uint32(n)
					}
				}
			}
		}
		return 0
	}
	waitFor := func(what string, d time.Duration, cond func() bool) time.Duration {
		t.Helper()
		start := time.Now()
		for !cond() {
			if time.Since(start) > d {
				t.Fatalf("%s: not within %s", what, d)
			}
			time.Sleep(100 * time.Millisecond)
		}
		return time.Since(start)
	}

	// 1. `gcc` with the same CPU profile: no signature finding.
	run("/tmp/launch-b")
	time.Sleep(3 * time.Second)
	if got := sigFindings(); len(got) != 0 {
		t.Fatalf("gcc stub raised %+v, want no signature finding", got[0])
	}

	// 2. `xmrig --donate-level 1`: finding within 10 s with the exec in
	// evidence, killed and audited by pid.
	run("/tmp/launch-a")
	took := waitFor("MINER_SIGNATURE finding for xmrig", 10*time.Second, func() bool { return len(sigFindings()) > 0 })
	f := sigFindings()[0]
	t.Logf("finding after %s: subject=%s", took.Round(time.Millisecond), f.Subject)
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH || f.Container != name || len(f.Evidence.Execs) == 0 {
		t.Fatalf("finding = %+v", f)
	}
	if ex := f.Evidence.Execs[0]; ex.Filename != "/tmp/xmrig" || !strings.Contains(ex.Argv, "--donate-level 1") || ex.PID == 0 {
		t.Fatalf("exec evidence = %+v, want the xmrig stub itself", ex)
	}
	waitFor("audited kill of /tmp/xmrig", 10*time.Second, func() bool { return killedPIDFor("/tmp/xmrig") != 0 })
	pid := killedPIDFor("/tmp/xmrig")
	if pid != f.Evidence.Execs[0].PID {
		t.Fatalf("killed pid %d, but the matched exec was pid %d", pid, f.Evidence.Execs[0].PID)
	}
	waitFor("killed pid gone from /proc", 5*time.Second, func() bool {
		_, err := os.Stat(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10)))
		return os.IsNotExist(err)
	})
	if _, _, code, err := client.ExecWithExitCode(name, []string{"pgrep", "-f", "/tmp/xmrig"}); err == nil && code == 0 {
		t.Fatal("an xmrig process is still running in the box")
	}
	waitFor("finding marked process_killed", 5*time.Second, func() bool {
		g := sigFindings()[0]
		return g.Response != nil && g.Response.ProcessKilled
	})

	// 3. A renamed binary with stratum+tcp:// in argv is still caught.
	run("/tmp/launch-c")
	waitFor("argv:stratum+tcp:// finding for the renamed binary", 10*time.Second, func() bool {
		for _, g := range sigFindings() {
			if g.Subject == "argv:stratum+tcp://" {
				return true
			}
		}
		return false
	})
}
