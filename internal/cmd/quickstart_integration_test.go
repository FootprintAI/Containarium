package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These are hermetic orchestration tests: they drive the whole runQuickstart
// flow — step order, flag wiring, the files it writes, the argv it would
// launch — with the daemon RPCs and the agent exec replaced by recording
// seams. No daemon, no Incus, no real agent; safe to run in CI as a normal
// unit test. The daemon/Incus- and installer-level integration tests live
// separately (see the PR description) because they need real infrastructure.

type qsRecord struct {
	createCalled bool
	createName   string
	createSSHKey string
	createStack  string
	syncCalled   bool
	exposeCalled bool
	exposeName   string
	exposePort   int
	exposeDomain string
	launchCalled bool
	launchAgent  string
	launchInstr  string
	// key wait (#2013)
	waitCalled       bool
	waitName         string
	waitBeforeLaunch bool
}

// installQuickstartHarness resets the quickstart flag globals to their init
// defaults, points HOME at a temp dir (no sudo), and swaps the four
// side-effecting seams for recorders. Everything is restored on cleanup so the
// rest of the cmd package's tests are unaffected.
func installQuickstartHarness(t *testing.T) (*qsRecord, string) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SUDO_USER", "")

	oKey, oStack, oCPU, oMem := qsSSHKeyPath, qsStack, qsCPU, qsMemory
	oSent, oPrompt, oDom, oAgent, oName := qsSentinel, qsPrompt, qsDomain, qsAgent, qsAgentName
	oExpose, oSkipMCP, oSkipInc, oNoLaunch := qsExposePort, qsSkipMCP, qsSkipInclude, qsNoLaunch
	oServer := serverAddr
	oCreate, oSync, oExposeFn, oLaunch := qsStepCreate, qsStepSSHConfig, qsStepExposePort, qsStepLaunchAgent
	oWait := qsStepWaitForKey
	t.Cleanup(func() {
		qsSSHKeyPath, qsStack, qsCPU, qsMemory = oKey, oStack, oCPU, oMem
		qsSentinel, qsPrompt, qsDomain, qsAgent, qsAgentName = oSent, oPrompt, oDom, oAgent, oName
		qsExposePort, qsSkipMCP, qsSkipInclude, qsNoLaunch = oExpose, oSkipMCP, oSkipInc, oNoLaunch
		serverAddr = oServer
		qsStepCreate, qsStepSSHConfig, qsStepExposePort, qsStepLaunchAgent = oCreate, oSync, oExposeFn, oLaunch
		qsStepWaitForKey = oWait
	})

	// Defaults mirror init().
	qsSSHKeyPath, qsStack, qsCPU, qsMemory = "", "fullstack", "4", "4GB"
	qsSentinel, qsPrompt, qsDomain, qsAgent, qsAgentName = "", "", "", "claude", "containarium-box"
	qsExposePort, qsSkipMCP, qsSkipInclude, qsNoLaunch = 8080, false, false, false
	serverAddr = ""

	rec := &qsRecord{}
	qsStepCreate = func(_ *cobra.Command, args []string) error {
		rec.createCalled = true
		rec.createName = args[0]
		rec.createSSHKey = sshKeyPath // set by runQuickstart before the call
		rec.createStack = stackID
		return nil
	}
	qsStepSSHConfig = func(_ *cobra.Command, _ []string) error { rec.syncCalled = true; return nil }
	qsStepExposePort = func(_ *cobra.Command, args []string) error {
		rec.exposeCalled = true
		rec.exposeName = args[0]
		rec.exposePort = exposePortPort
		rec.exposeDomain = exposePortDomain
		return nil
	}
	qsStepWaitForKey = func(_ context.Context, name, _ string) error {
		rec.waitCalled = true
		rec.waitName = name
		rec.waitBeforeLaunch = !rec.launchCalled
		return nil
	}
	qsStepLaunchAgent = func(agent, instr string) error {
		rec.launchCalled = true
		rec.launchAgent = agent
		rec.launchInstr = instr
		return nil
	}
	return rec, home
}

func TestQuickstartIntegration_WiresEverything(t *testing.T) {
	rec, home := installQuickstartHarness(t)
	qsStack = "nodejs"

	// A pre-existing gemini config should also get wired (agent-switch-later).
	geminiCfg := filepath.Join(home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(geminiCfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geminiCfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runQuickstart(quickstartCmd, []string{"alice"}); err != nil {
		t.Fatalf("runQuickstart: %v", err)
	}

	// Step 1: create, with an auto-provisioned managed pubkey and our stack.
	if !rec.createCalled || rec.createName != "alice" {
		t.Fatalf("create not called for alice: %+v", rec)
	}
	if !strings.HasSuffix(rec.createSSHKey, ".pub") {
		t.Fatalf("create should receive a managed pubkey, got %q", rec.createSSHKey)
	}
	if rec.createStack != "nodejs" {
		t.Fatalf("stack = %q, want nodejs", rec.createStack)
	}

	// Step 2: sync + a real Include line + a real managed private key on disk.
	if !rec.syncCalled {
		t.Fatal("ssh-config sync not called")
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "containarium_ed25519")); err != nil {
		t.Fatalf("managed private key not generated: %v", err)
	}
	cfg := readFile(t, filepath.Join(home, ".ssh", "config"))
	if want := "Include " + filepath.Join(home, ".containarium", "ssh_config"); !strings.Contains(cfg, want) {
		t.Fatalf("Include not wired into ~/.ssh/config:\n%s", cfg)
	}

	// Step 3: MCP wired for the primary (claude) and the present extra (gemini).
	if c := readFile(t, filepath.Join(home, ".claude.json")); !strings.Contains(c, "containarium-box") {
		t.Fatalf("claude MCP config not wired:\n%s", c)
	}
	if g := readFile(t, geminiCfg); !strings.Contains(g, "containarium-box") {
		t.Fatalf("gemini MCP config not wired:\n%s", g)
	}

	// No --prompt → no expose, no launch.
	if rec.exposeCalled || rec.launchCalled {
		t.Fatalf("expose/launch must not run without --prompt: %+v", rec)
	}
}

func TestQuickstartIntegration_PromptExposesAndLaunches(t *testing.T) {
	rec, _ := installQuickstartHarness(t)

	// Register a fake agent whose binary ("true") is always on PATH, so the
	// pre-create fail-fast (resolveAgent → exec.LookPath) passes without a real
	// claude install. The launch itself is captured by the seam.
	agentSpecs["fake"] = agentSpec{
		bin:           "true",
		launchArgs:    func(p string) []string { return []string{p} },
		mcpConfigPath: func(h string) string { return filepath.Join(h, ".fake.json") },
		wireMCP: func(path, name, host string) (bool, error) {
			return mergeMCPServerJSON(path, "mcpServers", name, host)
		},
	}
	t.Cleanup(func() { delete(agentSpecs, "fake") })

	qsAgent = "fake"
	qsPrompt = "a coffee shop landing page"
	qsDomain = "coffee.example.com"
	qsExposePort = 8080
	serverAddr = "vm.example.com" // enables the expose step (route op needs --server)

	if err := runQuickstart(quickstartCmd, []string{"alice"}); err != nil {
		t.Fatalf("runQuickstart: %v", err)
	}

	if !rec.exposeCalled || rec.exposeName != "alice" || rec.exposePort != 8080 || rec.exposeDomain != "coffee.example.com" {
		t.Fatalf("expose wired wrong: %+v", rec)
	}
	if !rec.launchCalled || rec.launchAgent != "fake" {
		t.Fatalf("agent launch not invoked: %+v", rec)
	}
	if !strings.Contains(rec.launchInstr, "a coffee shop landing page") ||
		!strings.Contains(rec.launchInstr, "https://coffee.example.com/") {
		t.Fatalf("launch instruction missing prompt/url:\n%s", rec.launchInstr)
	}
}

func TestQuickstartIntegration_PromptWithoutURLFailsBeforeCreate(t *testing.T) {
	rec, _ := installQuickstartHarness(t)
	qsPrompt = "x"
	qsDomain = ""
	qsExposePort = 8080 // non-zero + no domain → must error

	if err := runQuickstart(quickstartCmd, []string{"alice"}); err == nil {
		t.Fatal("expected an error when --prompt has no public URL")
	}
	if rec.createCalled {
		t.Fatal("must fail before creating a box")
	}
}

func TestQuickstartIntegration_NoMCPAndNoInclude(t *testing.T) {
	rec, home := installQuickstartHarness(t)
	qsSkipMCP = true
	qsSkipInclude = true

	if err := runQuickstart(quickstartCmd, []string{"alice"}); err != nil {
		t.Fatalf("runQuickstart: %v", err)
	}
	if !rec.createCalled {
		t.Fatal("create should still run")
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "config")); !os.IsNotExist(err) {
		t.Fatalf("--no-ssh-include should not write ~/.ssh/config (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); !os.IsNotExist(err) {
		t.Fatalf("--no-mcp should not write ~/.claude.json (err=%v)", err)
	}
}

// registerFakeAgent adds an agent whose binary ("true") is always on PATH.
func registerFakeAgent(t *testing.T) {
	t.Helper()
	agentSpecs["fake"] = agentSpec{
		bin:           "true",
		launchArgs:    func(p string) []string { return []string{p} },
		mcpConfigPath: func(h string) string { return filepath.Join(h, ".fake.json") },
		wireMCP: func(path, name, host string) (bool, error) {
			return mergeMCPServerJSON(path, "mcpServers", name, host)
		},
	}
	t.Cleanup(func() { delete(agentSpecs, "fake") })
}

// #2013: quickstart that just created the box waits out key propagation
// through the sentinel BEFORE handing off to the agent (whose first act is
// `ssh <box> agent-box`); a reused box, direct mode, or no launch never waits.
func TestQuickstartIntegration_KeyWaitBeforeLaunch(t *testing.T) {
	tests := []struct {
		name     string
		sentinel string
		existing bool
		noLaunch bool
		wantWait bool
	}{
		{name: "created via sentinel, launching: waits first", sentinel: "sentinel.example.com", wantWait: true},
		{name: "box already existed: fails once as today", sentinel: "sentinel.example.com", existing: true},
		{name: "direct mode: no sentinel, no keysync lag", sentinel: ""},
		{name: "--no-launch: quickstart itself never sshes", sentinel: "sentinel.example.com", noLaunch: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := installQuickstartHarness(t)
			registerFakeAgent(t)
			qsAgent, qsPrompt, qsExposePort = "fake", "a site", 0
			qsSentinel, qsNoLaunch = tc.sentinel, tc.noLaunch
			if tc.existing {
				qsStepCreate = func(*cobra.Command, []string) error {
					return status.Error(codes.AlreadyExists, "exists")
				}
			}
			if err := runQuickstart(quickstartCmd, []string{"alice"}); err != nil {
				t.Fatalf("runQuickstart: %v", err)
			}
			if rec.waitCalled != tc.wantWait {
				t.Fatalf("waited = %v, want %v", rec.waitCalled, tc.wantWait)
			}
			if tc.wantWait && (!rec.waitBeforeLaunch || rec.waitName != "alice" || !rec.launchCalled) {
				t.Fatalf("wait must precede the launch, for the box: %+v", rec)
			}
		})
	}
}

func TestQuickstartIntegration_KeyNeverLearnedStopsBeforeLaunch(t *testing.T) {
	rec, _ := installQuickstartHarness(t)
	registerFakeAgent(t)
	qsAgent, qsPrompt, qsExposePort, qsSentinel = "fake", "a site", 0, "sentinel.example.com"
	qsStepWaitForKey = func(context.Context, string, string) error {
		return fmt.Errorf("%w after waiting 2m30s", connectcore.ErrKeyNotLearned)
	}
	err := runQuickstart(quickstartCmd, []string{"alice"})
	if !errors.Is(err, connectcore.ErrKeyNotLearned) {
		t.Fatalf("err = %v, want ErrKeyNotLearned", err)
	}
	if rec.launchCalled {
		t.Fatal("must not launch the agent onto a box it cannot reach")
	}
}
