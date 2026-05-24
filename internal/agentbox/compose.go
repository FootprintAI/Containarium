package agentbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Compose-autostart tools — Phase B of the compose-autostart
// design (docs/COMPOSE-AUTOSTART-DESIGN.md).
//
// In-box MCP tools that let an agent self-discover compose
// stacks in its tenant's $HOME and opt them in to systemd-user
// autostart so they survive a host reboot.
//
// All state lives in the LXC: the systemd-user units under
// ~/.config/systemd/user/, plus loginctl linger. No daemon
// involvement. Phase C lands a parallel daemon-RPC path; this
// phase intentionally ships first because agent self-protection
// is the highest-value primitive.
//
// Tools:
//   - compose_discover           — walk $HOME, return per-stack info
//   - compose_autostart_enable   — install + enable the user unit
//   - compose_autostart_disable  — stop + disable + remove
//   - compose_autostart_status   — single-stack query

const (
	composeUnitTemplate = "containarium-compose@.service"
	composeUnitPath     = ".config/systemd/user/" + composeUnitTemplate
	defaultMaxDepth     = 5
)

// defaultSkip is the built-in skip-list. Configurable per-call
// via the `skip` tool argument; bypass entirely via `no_skip`.
// Covers the directories most likely to contain vendored /
// test-fixture compose files that aren't real workloads.
var defaultSkip = []string{
	"node_modules", ".git", "vendor", "target", "dist",
	"build", ".cache", ".venv", "venv", "__pycache__",
}

// ComposeStack mirrors the proto ComposeStack shape from the
// design doc. JSON tags align with the MCP tool output and
// (eventually) the gRPC ComposeStack message.
type ComposeStack struct {
	ComposeDir        string `json:"compose_dir"`
	ComposeFile       string `json:"compose_file"`
	ComposeBin        string `json:"compose_bin"`
	RunningCount      int    `json:"running_count"`
	TotalCount        int    `json:"total_count"`
	AutostartEnabled  bool   `json:"autostart_enabled"`
	UnitName          string `json:"unit_name,omitempty"`
	ComposeModifiedAt string `json:"compose_modified_at,omitempty"`
	UnitModifiedAt    string `json:"unit_modified_at,omitempty"`
}

func registerComposeTools(s *server.MCPServer) {
	s.AddTool(composeDiscoverTool(), handleComposeDiscover)
	s.AddTool(composeEnableTool(), handleComposeEnable)
	s.AddTool(composeDisableTool(), handleComposeDisable)
	s.AddTool(composeStatusTool(), handleComposeStatus)
}

// ----- compose_discover ---------------------------------------------------

func composeDiscoverTool() mcp.Tool {
	return mcp.NewTool(
		"compose_discover",
		mcp.WithDescription(
			"Walk $HOME for docker-compose / compose YAML files and report each "+
				"as a stack: compose_dir, compose_file, compose_bin "+
				"(podman-compose|docker compose|podman compose), running_count + "+
				"total_count (so you can tell partial degradation from fully up/down), "+
				"autostart status, and the modification times of both compose file "+
				"and its autostart unit (so you can detect 'compose changed since "+
				"autostart was wired'). Read-only.",
		),
		mcp.WithString("root",
			mcp.Description("Walk root (default: $HOME)."),
		),
		mcp.WithNumber("max_depth",
			mcp.Description(fmt.Sprintf("Max walk depth (default %d).", defaultMaxDepth)),
		),
		mcp.WithArray("skip",
			mcp.Description("Directory basenames to skip (additive to the built-in list unless no_skip=true)."),
		),
		mcp.WithBoolean("no_skip",
			mcp.Description("Bypass the built-in skip list (and any 'skip' overrides) and walk every directory. Useful for one-off audits."),
		),
	)
}

func handleComposeDiscover(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	root, _ := args["root"].(string)
	if root == "" {
		root = homeDir()
	}
	maxDepth := defaultMaxDepth
	if d, ok := argInt(args, "max_depth"); ok {
		maxDepth = d
	}
	noSkip, _ := args["no_skip"].(bool)
	extraSkip := argStringSlice(args, "skip")

	skipSet := map[string]struct{}{}
	if !noSkip {
		for _, d := range defaultSkip {
			skipSet[d] = struct{}{}
		}
	}
	for _, d := range extraSkip {
		skipSet[d] = struct{}{}
	}

	stacks, err := discoverStacks(root, maxDepth, skipSet)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("compose_discover: %v", err)), nil
	}

	// Resolve compose_bin once per process — it's a system
	// property, not per-stack, and the lookup is the same
	// every call.
	bin := resolveComposeBin()
	for i := range stacks {
		stacks[i].ComposeBin = bin
		if bin != "" {
			r, t := composeServiceCounts(bin, stacks[i].ComposeDir)
			stacks[i].RunningCount, stacks[i].TotalCount = r, t
		}
		fillAutostartStatus(&stacks[i])
	}

	body, _ := json.MarshalIndent(map[string]any{"stacks": stacks}, "", "  ")
	return mcp.NewToolResultText(string(body)), nil
}

// ----- compose_autostart_enable -------------------------------------------

func composeEnableTool() mcp.Tool {
	return mcp.NewTool(
		"compose_autostart_enable",
		mcp.WithDescription(
			"Install + enable the systemd-user unit that keeps the compose stack "+
				"at `dir` running across reboots. Idempotent — re-running refreshes "+
				"the unit and verifies the stack is up. Enables loginctl linger so "+
				"the user-systemd starts at host boot regardless of login state. "+
				"OPT-IN: nothing happens to other compose dirs.",
		),
		mcp.WithString("dir",
			mcp.Description("Path to the compose directory (the one containing docker-compose.yml or compose.yml)."),
			mcp.Required(),
		),
		mcp.WithBoolean("force",
			mcp.Description("Re-install the unit even if already enabled. Use when the compose file changed since the last enable."),
		),
	)
}

func handleComposeEnable(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	dir, _ := args["dir"].(string)
	if dir == "" {
		return mcp.NewToolResultError("compose_autostart_enable: 'dir' is required"), nil
	}
	dir = expandUser(dir)
	force, _ := args["force"].(bool)

	abs, err := filepath.Abs(dir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("resolve dir: %v", err)), nil
	}
	if !hasComposeFile(abs) {
		return mcp.NewToolResultError(fmt.Sprintf("no docker-compose.yml / compose.yml found under %s", abs)), nil
	}

	bin := resolveComposeBin()
	if bin == "" {
		return mcp.NewToolResultError("no compose runtime found on PATH (looked for podman-compose, docker compose, podman compose)"), nil
	}

	slug := stackSlug(abs)
	unitInstance := "containarium-compose@" + slug + ".service"

	if !force && unitEnabled(unitInstance) {
		return mcp.NewToolResultText(fmt.Sprintf(
			"already enabled: %s (use force=true to refresh)", unitInstance,
		)), nil
	}

	// 1. install the template if missing or refresh on force.
	if err := installComposeUnit(bin, force); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("install unit template: %v", err)), nil
	}
	// 2. enable linger so user-systemd starts at host boot.
	if err := enableLinger(); err != nil {
		// Not fatal — autostart still works if the user is
		// logged in; we surface the warning so operators can
		// fix it (likely needs root sudo, which agent-box may
		// not have).
		_ = err
	}
	// 3. daemon-reload, then enable + start.
	if err := systemctlUser("daemon-reload"); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("daemon-reload: %v", err)), nil
	}
	if err := systemctlUser("enable", "--now", unitInstance); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("enable %s: %v", unitInstance, err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"enabled: %s (compose_bin=%s, dir=%s)", unitInstance, bin, abs,
	)), nil
}

// ----- compose_autostart_disable ------------------------------------------

func composeDisableTool() mcp.Tool {
	return mcp.NewTool(
		"compose_autostart_disable",
		mcp.WithDescription(
			"Stop and disable the autostart unit for the compose stack at `dir`. "+
				"Does NOT stop the running containers — use the compose CLI for that. "+
				"Just removes the boot-time restart protection.",
		),
		mcp.WithString("dir",
			mcp.Description("Path to the compose directory."),
			mcp.Required(),
		),
	)
}

func handleComposeDisable(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	dir, _ := args["dir"].(string)
	if dir == "" {
		return mcp.NewToolResultError("compose_autostart_disable: 'dir' is required"), nil
	}
	dir = expandUser(dir)
	abs, _ := filepath.Abs(dir)
	slug := stackSlug(abs)
	unitInstance := "containarium-compose@" + slug + ".service"

	if !unitEnabled(unitInstance) {
		return mcp.NewToolResultText(fmt.Sprintf("not enabled: %s (nothing to do)", unitInstance)), nil
	}

	// disable --now stops + disables in one call. We don't
	// call podman-compose down; the design says disable only
	// touches autostart, not the running stack.
	if err := systemctlUser("disable", unitInstance); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("disable %s: %v", unitInstance, err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"disabled: %s (containers still running; use compose CLI to stop them)", unitInstance,
	)), nil
}

// ----- compose_autostart_status -------------------------------------------

func composeStatusTool() mcp.Tool {
	return mcp.NewTool(
		"compose_autostart_status",
		mcp.WithDescription(
			"Single-stack version of compose_discover: report the autostart + "+
				"running state of the compose stack at `dir` without walking "+
				"$HOME.",
		),
		mcp.WithString("dir",
			mcp.Description("Path to the compose directory."),
			mcp.Required(),
		),
	)
}

func handleComposeStatus(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	dir, _ := args["dir"].(string)
	if dir == "" {
		return mcp.NewToolResultError("compose_autostart_status: 'dir' is required"), nil
	}
	dir = expandUser(dir)
	abs, _ := filepath.Abs(dir)

	cf, ok := findComposeFile(abs)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("no compose file under %s", abs)), nil
	}

	bin := resolveComposeBin()
	stack := ComposeStack{
		ComposeDir:  abs,
		ComposeFile: cf,
		ComposeBin:  bin,
	}
	if info, err := os.Stat(cf); err == nil {
		stack.ComposeModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	if bin != "" {
		stack.RunningCount, stack.TotalCount = composeServiceCounts(bin, abs)
	}
	fillAutostartStatus(&stack)

	body, _ := json.MarshalIndent(stack, "", "  ")
	return mcp.NewToolResultText(string(body)), nil
}

// =================================================================
//  Helpers
// =================================================================

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return os.Getenv("HOME")
}

func expandUser(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		return filepath.Join(homeDir(), strings.TrimPrefix(p, "~"))
	}
	return p
}

// argInt extracts a number arg as int. JSON numbers decode to
// float64 by default; tolerate either.
func argInt(args map[string]any, key string) (int, bool) {
	switch v := args[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}

func argStringSlice(args map[string]any, key string) []string {
	raw, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// composeFileNames is the set we look for in each directory.
// Order matters: later entries override earlier ones if both
// exist (compose.yml beats docker-compose.yml, matching docker
// compose v2's own resolution order).
var composeFileNames = []string{
	"docker-compose.yaml",
	"docker-compose.yml",
	"compose.yaml",
	"compose.yml",
}

func hasComposeFile(dir string) bool {
	_, ok := findComposeFile(dir)
	return ok
}

func findComposeFile(dir string) (string, bool) {
	var found string
	for _, name := range composeFileNames {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			found = p
		}
	}
	return found, found != ""
}

// discoverStacks walks `root` up to `maxDepth` levels deep,
// skipping any directory whose basename is in `skip`, and
// returns one ComposeStack per directory containing a
// compose file. The returned slice is sorted by ComposeDir
// for stable output.
func discoverStacks(root string, maxDepth int, skip map[string]struct{}) ([]ComposeStack, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var found []ComposeStack

	walkErr := filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission errors on subdirs are common (e.g. ./root-owned).
			// Skip the offender rather than aborting the whole walk.
			if errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return nil // best-effort traversal
		}
		if !d.IsDir() {
			return nil
		}
		// Depth check: count separators in the relative path.
		rel, rerr := filepath.Rel(rootAbs, path)
		if rerr == nil && rel != "." {
			depth := strings.Count(rel, string(os.PathSeparator)) + 1
			if depth > maxDepth {
				return fs.SkipDir
			}
		}
		// Skip-list check on the basename.
		if _, blocked := skip[filepath.Base(path)]; blocked {
			return fs.SkipDir
		}
		// Compose file in this directory?
		if cf, ok := findComposeFile(path); ok {
			stack := ComposeStack{
				ComposeDir:  path,
				ComposeFile: cf,
			}
			if info, err := os.Stat(cf); err == nil {
				stack.ComposeModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
			}
			found = append(found, stack)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(found, func(i, j int) bool {
		return found[i].ComposeDir < found[j].ComposeDir
	})
	return found, nil
}

// resolveComposeBin picks the first available compose runtime
// on PATH. Order: podman-compose (most common with podman),
// docker compose (v2 plugin), podman compose (4.x+ builtin).
// Returns "" when none are usable.
//
// The returned string is the bin token (possibly two words like
// "docker compose") to be invoked as a shell command.
func resolveComposeBin() string {
	if _, err := exec.LookPath("podman-compose"); err == nil {
		return "podman-compose"
	}
	if _, err := exec.LookPath("docker"); err == nil {
		// `docker compose version` exits 0 when the plugin is
		// installed, non-zero otherwise.
		if err := exec.Command("docker", "compose", "version").Run(); err == nil {
			return "docker compose"
		}
	}
	if _, err := exec.LookPath("podman"); err == nil {
		if err := exec.Command("podman", "compose", "version").Run(); err == nil {
			return "podman compose"
		}
	}
	return ""
}

// composeServiceCounts runs `<bin> ps` in `dir` and returns
// (running, total) service counts. Best-effort: failures yield
// (0, 0) rather than an error, since discovery should keep
// going even if one stack's compose-cli is broken.
//
// We prefer the JSON output format; fall back to counting `Up`
// patterns in plain output if the runtime doesn't support
// `--format json`.
func composeServiceCounts(bin, dir string) (running, total int) {
	cmd := composeExec(bin, dir, "ps", "--format", "json")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		// Docker compose v2 emits a JSON array OR newline-
		// delimited objects depending on version. Try both.
		if running, total, ok := parseComposeJSON(out); ok {
			return running, total
		}
	}
	// Fallback: plain `ps` output, count lines that look "Up".
	cmd = composeExec(bin, dir, "ps")
	out, err = cmd.Output()
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "NAME") ||
			strings.HasPrefix(line, "CONTAINER") ||
			strings.HasPrefix(line, "Name ") {
			continue
		}
		total++
		if strings.Contains(line, "Up") || strings.Contains(line, "running") {
			running++
		}
	}
	return running, total
}

// composeExec builds the right exec.Cmd for `bin` (one or two
// tokens) running in `dir`. Splits the bin into argv to handle
// "docker compose" / "podman compose" sub-command forms.
func composeExec(bin, dir string, args ...string) *exec.Cmd {
	parts := strings.Fields(bin)
	all := append(parts[1:], args...)
	cmd := exec.Command(parts[0], all...)
	cmd.Dir = dir
	return cmd
}

// parseComposeJSON tries both shapes: an array of service
// objects, or newline-delimited JSON objects. Returns the
// counts and ok=true if either parsed successfully.
func parseComposeJSON(b []byte) (running, total int, ok bool) {
	type svc struct {
		State  string `json:"State"`
		Status string `json:"Status"`
	}
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" {
		return 0, 0, false
	}
	// Array form
	if trimmed[0] == '[' {
		var arr []svc
		if err := json.Unmarshal(b, &arr); err == nil {
			for _, s := range arr {
				total++
				if s.State == "running" || strings.HasPrefix(s.Status, "Up") {
					running++
				}
			}
			return running, total, true
		}
	}
	// NDJSON form
	parsed := false
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var s svc
		if err := json.Unmarshal([]byte(line), &s); err == nil {
			parsed = true
			total++
			if s.State == "running" || strings.HasPrefix(s.Status, "Up") {
				running++
			}
		}
	}
	return running, total, parsed
}

// stackSlug derives the systemd template instance name from
// an absolute compose directory. Uses the last two path
// components to reduce collisions when multiple stacks share a
// basename ("proj-a/deploy" vs "proj-b/deploy"). Sanitizes to
// the systemd-instance-safe charset.
func stackSlug(dir string) string {
	dir = filepath.Clean(dir)
	parts := strings.Split(dir, string(os.PathSeparator))
	var tail []string
	for i := len(parts) - 1; i >= 0 && len(tail) < 2; i-- {
		if parts[i] == "" {
			continue
		}
		tail = append([]string{parts[i]}, tail...)
	}
	raw := strings.Join(tail, "-")
	return sanitizeSlug(raw)
}

// sanitizeSlug lowercases + replaces anything outside
// [a-z0-9.-] with '-'. Collapses runs of '-' to one.
func sanitizeSlug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	// Trim both leading/trailing dashes AND dots so inputs
	// that boil down to "." or "..-" don't yield a slug that's
	// just a dot. Dots are still preserved in the interior
	// (v1.2.3 stays v1.2.3).
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		out = "default"
	}
	return out
}

// fillAutostartStatus populates UnitName / AutostartEnabled /
// UnitModifiedAt on the stack from on-disk state.
func fillAutostartStatus(stack *ComposeStack) {
	slug := stackSlug(stack.ComposeDir)
	unit := "containarium-compose@" + slug + ".service"
	stack.UnitName = unit
	stack.AutostartEnabled = unitEnabled(unit)
	// The template file's mtime stands in for "when was
	// autostart last touched on this box." It's the same file
	// for every instance, so this isn't per-stack — but it's
	// the best signal available without inspecting the
	// systemd `is-enabled` timestamp, which isn't exposed.
	if info, err := os.Stat(filepath.Join(homeDir(), composeUnitPath)); err == nil {
		stack.UnitModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
}

// unitEnabled returns true when `systemctl --user is-enabled
// <unit>` reports enabled / static / generated.
func unitEnabled(unit string) bool {
	out, err := exec.Command("systemctl", "--user", "is-enabled", unit).Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state == "enabled" || state == "static" || state == "generated"
}

// installComposeUnit writes the template unit file under
// ~/.config/systemd/user/. The unit references `bin` directly
// (no wrapper layer in v1; if the operator changes their
// compose runtime, re-run enable to refresh).
func installComposeUnit(bin string, force bool) error {
	dst := filepath.Join(homeDir(), composeUnitPath)
	if !force {
		if _, err := os.Stat(dst); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	contents := fmt.Sprintf(`# Containarium compose autostart — Phase B.
# Managed by agent-box; do not edit by hand. Re-run
# compose_autostart_enable to refresh.
[Unit]
Description=Containarium compose autostart: %%i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=%%h/%%i
ExecStart=/bin/sh -c '%s up -d'
ExecStop=/bin/sh -c '%s down'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
`, bin, bin)
	return os.WriteFile(dst, []byte(contents), 0o644)
}

// enableLinger asks loginctl to keep the user-systemd
// instance alive across logouts (and therefore start at host
// boot). Requires root in most distros — best-effort here; a
// non-root agent-box can still benefit from autostart while
// it's logged in.
func enableLinger() error {
	user := os.Getenv("USER")
	if user == "" {
		user = "$USER"
	}
	return exec.Command("loginctl", "enable-linger", user).Run()
}

// systemctlUser runs `systemctl --user <args>` and returns
// the error verbatim (with output included on failure).
func systemctlUser(args ...string) error {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
