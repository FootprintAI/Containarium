package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/spf13/cobra"
)

// quickstart collapses the README quick-start into one laptop-side command:
//
//  1. create a box                 (runCreate; remote via --server, or local)
//  2. write ~/.containarium/ssh_config + wire the Include line into
//     ~/.ssh/config                (runSSHConfigSync + ensureSSHInclude)
//  3. merge the agent-box entry into the caller's agent MCP config
//     (claude/gemini/codex)                          (agentSpec.wireMCP)
//  4. [--prompt] expose the URL, then LAUNCH the caller's own agent
//     on the build task                              (launchAgent)
//
// Topology (pure BYOA — decided): the LLM + the API key live on the LAPTOP.
// The box is a fresh Ubuntu container running agent-box (an MCP *server* — the
// hands, no brain). So --prompt cannot "seed a file and hope"; nothing in the
// box would read it. Instead quickstart runs on the laptop and, for --prompt,
// execs the laptop's own agent, which step 3 has already wired to the box over
// MCP. The agent (brain, on laptop) drives agent-box tools (hands, in box).
//
// Consequently quickstart is a LAPTOP command, not the install.sh one-liner:
// the SSH wiring, the MCP merge, and the agent launch all configure the user's
// own machine. The `curl … | sudo bash` install path bootstraps the daemon (+
// optionally a first box) on the server and stops there — it has no agent and
// no key to launch, and the human isn't on that machine.
//
// It reuses the existing subcommands' RunE functions by setting their
// package-level flag vars — quickstart is orchestration, not new client code.
// Every step is idempotent so a re-run heals a partial setup.
var (
	qsSSHKeyPath  string
	qsStack       string
	qsCPU         string
	qsMemory      string
	qsSentinel    string
	qsPrompt      string
	qsDomain      string
	qsExposePort  int
	qsAgent       string
	qsAgentName   string
	qsSkipMCP     bool
	qsSkipInclude bool
	qsNoLaunch    bool
)

var quickstartCmd = &cobra.Command{
	Use:   "quickstart <name>",
	Short: "Create a box, wire SSH + your agent, and (optionally) build a site — in one step",
	Long: `Quickstart runs the whole README quick-start as a single idempotent command.

This is a LAPTOP command: it configures your machine (SSH + your agent's MCP
config) and, with --prompt, launches your local agent. It talks to a remote
daemon via --server, or drives a local Incus in single-machine dev.

    containarium quickstart alice --ssh-key ~/.ssh/id_ed25519.pub \
      --server vm.example.com

What it does, in order:
  1. create the box (no-op if it already exists)
  2. sync ~/.containarium/ssh_config AND add the one Include line to
     ~/.ssh/config for you (the manual edit the README asks for)
  3. merge a "containarium-box" MCP server into your agent's config
     (claude → ~/.claude.json, gemini → ~/.gemini/settings.json,
     codex → ~/.codex/config.toml) — so your agent reaches the box with
     no copy-paste
  4. print the exact next action

Build a site in the same step (--prompt):

    containarium quickstart alice --ssh-key ~/.ssh/id_ed25519.pub \
      --server vm.example.com \
      --prompt "a landing page for my coffee shop, dark theme" \
      --domain coffee.example.com --agent claude

--prompt exposes --domain, then launches YOUR local agent (--agent: claude,
gemini, or codex) on the task. The agent runs on your laptop with your key;
step 3 has already wired it to the box, so it builds by driving the box's
agent-box tools over MCP and serves on the exposed port — the public URL is
live when it's done. OSS ships no model key: the brain is always your agent,
on your laptop.

Note: the fresh-VM installer (curl … | sudo bash) only bootstraps the daemon.
The build step lives here, on the laptop where your agent and key are.`,
	Args: cobra.ExactArgs(1),
	RunE: runQuickstart,
}

func init() {
	rootCmd.AddCommand(quickstartCmd)

	quickstartCmd.Flags().StringVar(&qsSSHKeyPath, "ssh-key", "", "Path to SSH public key to seed into the box. Optional: if omitted, quickstart reuses your existing ~/.ssh key or generates a managed one (containarium_ed25519) — the private key stays on your laptop.")
	quickstartCmd.Flags().StringVar(&qsStack, "stack", "fullstack", "Software stack to install in the box (default fullstack so a web build has node/npm ready)")
	quickstartCmd.Flags().StringVar(&qsCPU, "cpu", "4", "CPU cores for the box")
	quickstartCmd.Flags().StringVar(&qsMemory, "memory", "4GB", "Memory for the box")
	quickstartCmd.Flags().StringVar(&qsSentinel, "sentinel", "", "Sentinel SSH endpoint for ssh_config routing (empty = direct mode)")

	quickstartCmd.Flags().StringVar(&qsPrompt, "prompt", "", "What to build. Exposes --domain and launches your local --agent on the task (BYOA — your agent, your key, on your laptop).")
	quickstartCmd.Flags().StringVar(&qsDomain, "domain", "", "Public hostname to expose the build on (required with --prompt unless --expose-port is 0). DNS for it must point at the sentinel.")
	quickstartCmd.Flags().IntVar(&qsExposePort, "expose-port", 8080, "Container port to expose for the build (0 disables the pre-expose)")

	quickstartCmd.Flags().StringVar(&qsAgent, "agent", "claude", "Which local agent to wire + launch for --prompt: claude, gemini, or codex. Must be installed on your laptop.")
	quickstartCmd.Flags().BoolVar(&qsNoLaunch, "no-launch", false, "With --prompt, do everything but launching the agent — print the command to run instead")

	quickstartCmd.Flags().StringVar(&qsAgentName, "agent-name", "containarium-box", "Name of the MCP server entry written into agent configs")
	quickstartCmd.Flags().BoolVar(&qsSkipMCP, "no-mcp", false, "Skip writing any agent MCP config")
	quickstartCmd.Flags().BoolVar(&qsSkipInclude, "no-ssh-include", false, "Skip appending the Include line to ~/.ssh/config (still writes ~/.containarium/ssh_config)")
}

// Seams: the side-effecting steps (daemon RPCs + the agent exec) are indirected
// through function vars so an integration test can substitute fakes and drive
// the whole orchestration — step order, flag wiring, file writes, the launched
// argv — without a daemon or a real agent. Production uses the real functions.
var (
	qsStepCreate      = runCreate
	qsStepSSHConfig   = runSSHConfigSync
	qsStepExposePort  = runExposePort
	qsStepLaunchAgent = launchAgent
)

func runQuickstart(cmd *cobra.Command, args []string) error {
	name := args[0]

	if _, ok := agentSpecs[qsAgent]; !ok {
		return fmt.Errorf("unknown --agent %q (supported: %s)", qsAgent, strings.Join(supportedAgents, ", "))
	}

	// Resolve the human's home even when running under sudo (local Incus dev
	// needs root). ssh_config, ~/.ssh/config and the MCP configs all belong to
	// the invoking user, NOT root — otherwise `ssh alice` and the agent wiring
	// silently land in /root and do nothing. Single biggest footgun; handle
	// it once here.
	home, uid, gid, err := invokingUserHome()
	if err != nil {
		return fmt.Errorf("resolve invoking user home: %w", err)
	}

	// Skip bring-your-own-ssh-key: with no --ssh-key, reuse the user's
	// existing ~/.ssh key or generate a managed one. The private key never
	// leaves the laptop; sshIdentity feeds ssh_config's IdentityFile so
	// `ssh <box>` works without the user touching a key at all.
	pubKey, sshIdentity, generatedKey, err := resolveSSHKey(home, qsSSHKeyPath)
	if err != nil {
		return fmt.Errorf("resolve SSH key: %w", err)
	}

	launching := qsPrompt != "" && !qsNoLaunch
	if qsPrompt != "" {
		if qsDomain == "" && qsExposePort != 0 {
			return fmt.Errorf("--prompt needs a public URL: pass --domain (or --expose-port 0 to skip pre-exposing)")
		}
		if launching {
			// Fail fast, BEFORE creating a box, if the agent binary isn't here
			// — the whole point of --prompt is that the launch lands.
			if _, err := resolveAgent(qsAgent); err != nil {
				return err
			}
		}
	}

	fmt.Printf("▶ quickstart %q\n\n", name)

	// ── Step 1: create ──────────────────────────────────────────────────
	// Reuse runCreate by populating its flag vars. --force stays off so a
	// re-run is a no-op on an existing box rather than a destructive recreate;
	// swallow the "already exists" error to stay idempotent.
	fmt.Println("① create box")
	if qsSSHKeyPath == "" {
		chownUnderHome(pubKey, uid, gid)
		chownUnderHome(sshIdentity, uid, gid)
		if generatedKey {
			fmt.Printf("  generated managed SSH key %s\n", sshIdentity)
		} else {
			fmt.Printf("  using existing SSH key %s\n", pubKey)
		}
	}
	sshKeyPath = pubKey
	stackID = qsStack
	cpuLimit = qsCPU
	memoryLimit = qsMemory
	enablePodman = true
	if err := qsStepCreate(cmd, args); err != nil {
		if !isAlreadyExists(err) {
			return fmt.Errorf("create: %w", err)
		}
		fmt.Printf("  box %q already exists — reusing\n", name)
	}

	// ── Step 2: ssh_config + Include ────────────────────────────────────
	fmt.Println("\n② wire SSH")
	sshConfigSentinel = qsSentinel
	sshConfigIdentity = sshIdentity // "" when the user brought their own key
	sshConfigOutPath = filepath.Join(home, ".containarium", "ssh_config")
	if err := qsStepSSHConfig(cmd, nil); err != nil {
		return fmt.Errorf("ssh-config sync: %w", err)
	}
	chownUnderHome(sshConfigOutPath, uid, gid)

	if !qsSkipInclude {
		added, err := ensureSSHInclude(filepath.Join(home, ".ssh", "config"), sshConfigOutPath, uid, gid)
		if err != nil {
			return fmt.Errorf("wire Include into ~/.ssh/config: %w", err)
		}
		if added {
			fmt.Printf("  added Include line to %s\n", filepath.Join(home, ".ssh", "config"))
		} else {
			fmt.Println("  Include line already present")
		}
	}

	// ── Step 3: agent MCP wiring ────────────────────────────────────────
	// Always wire the chosen --agent; also wire any OTHER supported agent
	// already configured on this machine, so switching agents later Just Works.
	if !qsSkipMCP {
		fmt.Println("\n③ point your agent at the box")
		for _, t := range agentMCPTargets(home, qsAgent) {
			changed, err := t.spec.wireMCP(t.path, qsAgentName, name)
			if err != nil {
				return fmt.Errorf("merge %s MCP config %s: %w", t.agent, t.path, err)
			}
			chownUnderHome(t.path, uid, gid)
			if changed {
				fmt.Printf("  wrote %q server into %s (%s)\n", qsAgentName, t.path, t.agent)
			} else {
				fmt.Printf("  %s already had %q — left as-is\n", t.path, qsAgentName)
			}
		}
	}

	// ── Step 4: --prompt → expose URL, then launch YOUR agent ───────────
	if qsPrompt != "" {
		fmt.Println("\n④ expose URL + launch your agent")
		if qsExposePort != 0 {
			// expose-port is a daemon route op — needs --server. In local mode
			// we can't reserve the hostname; tell the user to run it later.
			if serverAddr == "" {
				fmt.Printf("  (local mode) after the build, run:\n")
				fmt.Printf("    containarium expose-port %s --container-port %d --domain %s\n", name, qsExposePort, qsDomain)
			} else {
				exposePortPort = qsExposePort
				exposePortDomain = qsDomain
				exposePortDescription = "quickstart build"
				if err := qsStepExposePort(cmd, []string{name}); err != nil {
					return fmt.Errorf("pre-expose: %w", err)
				}
			}
		}

		instruction := buildInstruction(qsAgentName, qsPrompt, qsDomain, qsExposePort)
		if launching {
			// Hand off: replace this process with the user's agent so they land
			// straight in the session, already working. Never returns on success.
			return qsStepLaunchAgent(qsAgent, instruction)
		}
		// --no-launch: print the exact command instead of exec'ing it.
		spec := agentSpecs[qsAgent]
		fmt.Printf("  agent + box are wired. Build with:\n\n    %s\n", spec.pretty(instruction))
		return nil
	}

	printQuickstartNextSteps(name)
	return nil
}

// ─── new helpers: the logic quickstart adds on top of existing commands ───

// invokingUserHome returns the home dir + uid/gid of the human who ran the
// command, unwrapping sudo (local Incus dev runs as root). SUDO_USER points
// back at the real account. Falls back to the current user when not under
// sudo, returning uid/gid -1 to mean "leave ownership alone".
func invokingUserHome() (home string, uid, gid int, err error) {
	if su := os.Getenv("SUDO_USER"); su != "" && su != "root" {
		u, lookErr := user.Lookup(su)
		if lookErr != nil {
			return "", 0, 0, fmt.Errorf("lookup SUDO_USER %q: %w", su, lookErr)
		}
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
		return u.HomeDir, uid, gid, nil
	}
	h, e := os.UserHomeDir()
	if e != nil {
		return "", 0, 0, e
	}
	return h, -1, -1, nil
}

// resolveSSHKey picks the public key to seed into the box. If the user passed
// --ssh-key, use it verbatim (no managed identity — ssh_config falls back to
// the default identities). Otherwise reuse an existing personal ~/.ssh key or
// generate a containarium-managed one under <home>/.ssh, returning the private-
// key path (identity) so ssh_config can point IdentityFile at it. Idempotent:
// a second run locates the key the first run generated instead of regenerating.
func resolveSSHKey(home, userProvided string) (pubPath, identity string, generated bool, err error) {
	if userProvided != "" {
		return userProvided, "", false, nil
	}
	pp, _, gen, err := sshkey.LocateOrGenerate(sshkey.LocateOpts{HomeDir: home})
	if err != nil {
		return "", "", false, err
	}
	return pp, strings.TrimSuffix(pp, ".pub"), gen, nil
}

// chownUnderHome best-effort restores ownership to the invoking user for a
// file we wrote while (possibly) running as root. No-op when uid<0.
func chownUnderHome(path string, uid, gid int) {
	if uid < 0 {
		return
	}
	_ = os.Chown(path, uid, gid)
}

// ensureSSHInclude prepends `Include <includePath>` to ~/.ssh/config if no
// Include for that path is already present. Creates file (0600) and dir
// (0700) if missing. Returns whether it added the line. Idempotent.
func ensureSSHInclude(sshConfigPath, includePath string, uid, gid int) (bool, error) {
	dir := filepath.Dir(sshConfigPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	chownUnderHome(dir, uid, gid)

	existing, err := os.ReadFile(sshConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(existing)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Include ") && strings.Contains(line, includePath) {
			return false, nil
		}
	}

	// Prepend so the Include wins over later `Host *` catch-alls (OpenSSH
	// takes the first value for most keywords).
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Include %s\n", includePath))
	if len(existing) > 0 {
		if existing[len(existing)-1] != '\n' {
			b.WriteByte('\n')
		}
		b.Write(existing)
	}
	if err := os.WriteFile(sshConfigPath, []byte(b.String()), 0o600); err != nil {
		return false, err
	}
	chownUnderHome(sshConfigPath, uid, gid)
	return true, nil
}

// mcpServerEntry is the JSON shape claude/gemini expect: an ssh command that
// runs `agent-box` inside the named host and speaks MCP over stdio (README
// step 4).
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// mergeMCPServerJSON inserts (or leaves untouched) the box's MCP server under
// .<mcpKey>[name] in a JSON agent-config file, preserving every other key.
// Round-trips through a generic map so unrelated settings survive verbatim —
// the one legitimate map[string]any use (a foreign JSON doc we don't own).
// Used for claude (~/.claude.json) and gemini (~/.gemini/settings.json), which
// share the "mcpServers" object shape.
func mergeMCPServerJSON(path, mcpKey, name, sshHost string) (bool, error) {
	root := map[string]any{}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &root); err != nil {
				return false, fmt.Errorf("%s is not valid JSON: %w", path, err)
			}
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return false, err
		}
	default:
		return false, err
	}

	servers, _ := root[mcpKey].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	if _, present := servers[name]; present {
		return false, nil // don't clobber a user's existing entry
	}
	servers[name] = mcpServerEntry{Command: "ssh", Args: []string{sshHost, "agent-box"}}
	root[mcpKey] = servers

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// codexAppendMCP wires the box server into codex's TOML config
// (~/.codex/config.toml) under [mcp_servers.<name>]. codex uses TOML, not
// JSON, so we append a table rather than merge a map. Idempotent: if a table
// header for this name already exists we leave the file untouched (a full TOML
// merge would need a parser dependency; appending a fresh table is safe and
// dependency-free — TOML tables are order-independent).
//
// name/sshHost are box identifiers (already validated by create's naming
// rules), so they need no TOML escaping here.
func codexAppendMCP(path, name, sshHost string) (bool, error) {
	header := fmt.Sprintf("[mcp_servers.%s]", name)
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if strings.Contains(string(existing), header) {
			return false, nil
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return false, err
		}
	default:
		return false, err
	}

	var b strings.Builder
	if len(existing) > 0 {
		b.Write(existing)
		if existing[len(existing)-1] != '\n' {
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	b.WriteString(header + "\n")
	b.WriteString("command = \"ssh\"\n")
	b.WriteString(fmt.Sprintf("args = [%q, \"agent-box\"]\n", sshHost))

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// ─── agent launch (BYOA: your agent, your key, your laptop) ───────────────

// agentSpec describes how to wire + invoke a local agent CLI. The agent reads
// its MCP config from disk (step 3 writes it via wireMCP), so launchArgs does
// NOT pass an --mcp-config flag; the box is already wired.
type agentSpec struct {
	bin           string
	launchArgs    func(instruction string) []string
	mcpConfigPath func(home string) string
	wireMCP       func(path, name, sshHost string) (bool, error)
}

func (s agentSpec) pretty(instruction string) string {
	return s.bin + " " + strings.Join(s.launchArgs(instruction), " ")
}

// supportedAgents is the ordered set surfaced to users and iterated for
// deterministic wiring output.
var supportedAgents = []string{"claude", "gemini", "codex"}

// agentSpecs is the adapter table. All three take the opening instruction as a
// positional arg to seed an interactive session.
//
// TODO(quickstart): confirm the exact opening-prompt invocation for gemini and
// codex against their shipping CLIs before release (claude's positional prompt
// is confirmed). If a CLI wants a flag (e.g. `-p`), adjust launchArgs — the
// wiring/tests around it don't change.
var agentSpecs = map[string]agentSpec{
	"claude": {
		bin:           "claude",
		launchArgs:    func(p string) []string { return []string{p} },
		mcpConfigPath: func(h string) string { return filepath.Join(h, ".claude.json") },
		wireMCP: func(path, name, host string) (bool, error) {
			return mergeMCPServerJSON(path, "mcpServers", name, host)
		},
	},
	"gemini": {
		bin:           "gemini",
		launchArgs:    func(p string) []string { return []string{p} },
		mcpConfigPath: func(h string) string { return filepath.Join(h, ".gemini", "settings.json") },
		wireMCP: func(path, name, host string) (bool, error) {
			return mergeMCPServerJSON(path, "mcpServers", name, host)
		},
	},
	"codex": {
		bin:           "codex",
		launchArgs:    func(p string) []string { return []string{p} },
		mcpConfigPath: func(h string) string { return filepath.Join(h, ".codex", "config.toml") },
		wireMCP:       codexAppendMCP,
	},
}

// mcpTarget pairs a resolved config path with the agent that owns it.
type mcpTarget struct {
	agent string
	spec  agentSpec
	path  string
}

// agentMCPTargets returns the config files to wire: the chosen agent always,
// plus any other supported agent already configured on this machine (so a
// user who later switches agents finds the box already wired). Deterministic
// order (primary first, then supportedAgents order).
func agentMCPTargets(home, primary string) []mcpTarget {
	out := []mcpTarget{{agent: primary, spec: agentSpecs[primary], path: agentSpecs[primary].mcpConfigPath(home)}}
	for _, a := range supportedAgents {
		if a == primary {
			continue
		}
		spec := agentSpecs[a]
		if _, err := os.Stat(spec.mcpConfigPath(home)); err == nil {
			out = append(out, mcpTarget{agent: a, spec: spec, path: spec.mcpConfigPath(home)})
		}
	}
	return out
}

// resolveAgent looks up the spec AND confirms the binary is on PATH, so
// --prompt can fail fast before creating a box.
func resolveAgent(agent string) (agentSpec, error) {
	spec, ok := agentSpecs[agent]
	if !ok {
		return agentSpec{}, fmt.Errorf("unknown --agent %q (supported: %s)", agent, strings.Join(supportedAgents, ", "))
	}
	if _, err := exec.LookPath(spec.bin); err != nil {
		return agentSpec{}, fmt.Errorf("--agent %q selected but %q is not on PATH — install it or pass --no-launch to get the command to run", agent, spec.bin)
	}
	return spec, nil
}

// launchAgent replaces this process with the user's agent, dropping them into
// a session already working on the build. Uses syscall.Exec (not os/exec) so
// the terminal is handed straight over. Never returns on success.
func launchAgent(agent, instruction string) error {
	spec, err := resolveAgent(agent)
	if err != nil {
		return err
	}
	bin, err := exec.LookPath(spec.bin)
	if err != nil {
		return err
	}
	argv := append([]string{spec.bin}, spec.launchArgs(instruction)...)
	fmt.Printf("  launching %s on the task…\n\n", spec.bin)
	return syscall.Exec(bin, argv, os.Environ())
}

// buildInstruction is the opening message handed to the agent. It names the
// MCP server (so the agent uses the box's tools, which run inside the box) and
// pins the serve port + public URL so "done" means "live at that URL".
func buildInstruction(serverName, prompt, domain string, port int) string {
	url := "the exposed URL"
	if domain != "" {
		url = "https://" + domain + "/"
	}
	return fmt.Sprintf(
		"Use the %q MCP tools (they run inside a remote Containarium box) to build: %s. "+
			"Write files and run commands with those tools, install dependencies, and serve the app on container port %d. "+
			"It is exposed at %s, so once it's listening the site is live there.",
		serverName, prompt, port, url,
	)
}

func printQuickstartNextSteps(name string) {
	fmt.Println("\n✓ quickstart complete")
	fmt.Printf("  • ssh %s              # shell into the box\n", name)
	fmt.Printf("  • your agent now sees the %q box via MCP\n", qsAgentName)
	fmt.Printf("  • re-run with --prompt \"…\" --domain <host> to build + go live in one step\n")
}
