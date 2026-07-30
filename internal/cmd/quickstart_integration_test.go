package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
	t.Cleanup(func() {
		qsSSHKeyPath, qsStack, qsCPU, qsMemory = oKey, oStack, oCPU, oMem
		qsSentinel, qsPrompt, qsDomain, qsAgent, qsAgentName = oSent, oPrompt, oDom, oAgent, oName
		qsExposePort, qsSkipMCP, qsSkipInclude, qsNoLaunch = oExpose, oSkipMCP, oSkipInc, oNoLaunch
		serverAddr = oServer
		qsStepCreate, qsStepSSHConfig, qsStepExposePort, qsStepLaunchAgent = oCreate, oSync, oExposeFn, oLaunch
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
