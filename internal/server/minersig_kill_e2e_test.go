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

	engine := threatdetect.NewEngine(NewActingSink(findings, responder), "e2e", false, nil, nil)
	rule, err := threatdetect.NewMinerSignatureRule(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Register(rule)

	watcher := NewExecWatcher(engine.OnExec)
	if err := watcher.Start(ctx, obj); err != nil {
		t.Skipf("exec telemetry unavailable here: %v", err)
	}
	defer watcher.Stop()
	watcher.Reconcile([]incus.ContainerInfo{{Name: name, State: "Running", Pid: initPID, Tenant: "e2e"}})

	sh := func(script string) {
		t.Helper()
		if _, stderr, err := client.ExecWithOutput(name, []string{"sh", "-c", script}); err != nil {
			t.Fatalf("exec %q: %v (%s)", script, err, stderr)
		}
	}
	sh("printf '" + strings.ReplaceAll(minerStub, "\n", `\n`) + "' > /tmp/xmrig && cp /tmp/xmrig /tmp/gcc && chmod +x /tmp/xmrig /tmp/gcc")
	t.Cleanup(func() {
		_, _, _ = client.ExecWithOutput(name, []string{"sh", "-c", "pkill -f /tmp/xmrig; pkill -f /tmp/gcc; rm -f /tmp/xmrig /tmp/gcc"})
	})

	// 1. `gcc` with the same CPU profile: no signature finding.
	sh("nohup /tmp/gcc -O2 >/dev/null 2>&1 &")
	time.Sleep(3 * time.Second)
	if got := findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE); len(got) != 0 {
		t.Fatalf("gcc stub raised %+v, want no signature finding", got[0])
	}

	// 2. `xmrig --donate-level 1`: finding within 10 s, killed, audited.
	start := time.Now()
	sh("nohup /tmp/xmrig --donate-level 1 >/dev/null 2>&1 &")
	var f *threatdetect.Finding
	for time.Since(start) < 10*time.Second {
		if got := findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE); len(got) > 0 {
			f = got[0]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if f == nil {
		t.Fatal("no MINER_SIGNATURE finding within 10 s of the xmrig exec")
	}
	t.Logf("finding after %s: subject=%s", time.Since(start).Round(time.Millisecond), f.Subject)
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH || f.Container != name || len(f.Evidence.Execs) == 0 {
		t.Fatalf("finding = %+v", f)
	}
	ex := f.Evidence.Execs[len(f.Evidence.Execs)-1]
	if !strings.Contains(ex.Argv, "--donate-level 1") || ex.PID == 0 {
		t.Fatalf("exec evidence = %+v", ex)
	}
	if f.Response == nil || !f.Response.ProcessKilled {
		t.Fatalf("response = %+v, want process_killed", f.Response)
	}
	kills := auditDetails(auditLog, "kill")
	if len(kills) == 0 || !strings.Contains(kills[0], "pid="+strconv.FormatUint(uint64(ex.PID), 10)) {
		t.Fatalf("kill audit = %v, want one naming pid %d", kills, ex.PID)
	}
	gone := false
	for i := 0; i < 50 && !gone; i++ {
		if _, err := os.Stat(filepath.Join("/proc", strconv.FormatUint(uint64(ex.PID), 10))); os.IsNotExist(err) {
			gone = true
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !gone {
		t.Fatalf("pid %d still exists after the kill", ex.PID)
	}

	// 3. A renamed binary with stratum+tcp:// in argv is still caught.
	sh("cp /tmp/gcc /tmp/worker && chmod +x /tmp/worker && nohup /tmp/worker -o stratum+tcp://pool.invalid:3333 >/dev/null 2>&1 &")
	t.Cleanup(func() { _, _, _ = client.ExecWithOutput(name, []string{"sh", "-c", "pkill -f /tmp/worker; rm -f /tmp/worker"}) })
	deadline := time.Now().Add(10 * time.Second)
	for {
		hit := false
		for _, g := range findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE) {
			hit = hit || g.Subject == "argv:stratum+tcp://"
		}
		if hit {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("renamed binary with stratum+tcp:// argv raised no finding")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
