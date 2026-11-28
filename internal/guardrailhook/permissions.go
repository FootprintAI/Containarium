package guardrailhook

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The command wrapper puts a `trap` in front of a Bash command. Claude Code's
// permission check will not approve `trap` under any rule narrower than "all
// of Bash" ("'trap' evaluates arguments as shell code"), so under scoped
// rules such as Bash(git status *) a wrapped call is refused, every time.
// Checked live with Claude Code 2.1.332: a wrapped command runs when the
// settings allow all of Bash in the default, acceptEdits and dontAsk modes,
// and in bypassPermissions; it is not run in plan or auto mode; a deny rule
// still denies a wrapped command; an ask rule that matches the command turns
// the call into a refusal instead of a prompt. The hook cannot match rule
// patterns the way Claude Code does, so any Bash ask rule leaves commands
// alone. Rules given on the command line (--allowedTools, --settings) are not
// visible to a hook; those sessions are not wrapped, or are wrapped on the
// strength of the files alone.

// permissionModeBypass is the mode that approves every call.
const permissionModeBypass = "bypassPermissions"

// wrapModes are the permission modes in which a blanket Bash allow was seen
// to run a wrapped command. Any other mode, an absent one included, is not
// wrapped.
var wrapModes = map[string]bool{"default": true, "acceptEdits": true, "dontAsk": true}

// blanketBashRules allow every Bash command.
var blanketBashRules = map[string]bool{"Bash": true, "Bash(*)": true}

// SettingsFile is one Claude Code settings file. Managed marks enterprise
// managed settings, which can restrict permission rules to themselves.
type SettingsFile struct {
	Path    string
	Managed bool
}

type claudeSettings struct {
	// AllowManagedPermissionRulesOnly in managed settings makes the session
	// ignore permission rules from every other file. Read at the top level
	// and under permissions, so either placement is honoured.
	AllowManagedPermissionRulesOnly bool `json:"allowManagedPermissionRulesOnly"`
	Permissions                     struct {
		Allow                           []string `json:"allow"`
		Ask                             []string `json:"ask"`
		AllowManagedPermissionRulesOnly bool     `json:"allowManagedPermissionRulesOnly"`
	} `json:"permissions"`
}

// claudeRunsWrapped says whether Claude Code will run a wrapped Bash command
// in this session rather than refuse it. Every doubt answers no: an
// unwrapped command can leak a failed result, a refused one breaks every
// Bash call.
func (c *call) claudeRunsWrapped() bool {
	mode := c.in.PermissionMode
	bypass := mode == permissionModeBypass
	if !bypass && !wrapModes[mode] {
		return false
	}
	project := os.Getenv("CLAUDE_PROJECT_DIR")
	if project == "" {
		project = c.in.CWD
	}
	type loaded struct {
		claudeSettings
		managed bool
	}
	var files []loaded
	for _, f := range c.h.cfg.SettingsFiles(project) {
		raw, err := os.ReadFile(f.Path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		var s claudeSettings
		if err != nil || json.Unmarshal(raw, &s) != nil {
			// A file Claude Code reads but this hook cannot could hold an
			// ask rule.
			return false
		}
		files = append(files, loaded{s, f.Managed})
	}
	managedOnly := false
	for _, f := range files {
		if f.managed && (f.AllowManagedPermissionRulesOnly || f.Permissions.AllowManagedPermissionRulesOnly) {
			managedOnly = true
		}
	}
	blanket := bypass
	for _, f := range files {
		// Ask rules veto from any file, even one the session ignores under
		// managed-only: that errs toward not wrapping.
		for _, rule := range f.Permissions.Ask {
			if rule == "Bash" || strings.HasPrefix(rule, "Bash(") {
				return false
			}
		}
		if managedOnly && !f.managed {
			continue
		}
		for _, rule := range f.Permissions.Allow {
			if blanketBashRules[rule] {
				blanket = true
			}
		}
	}
	return blanket
}

// claudeSettingsFiles is the default Config.SettingsFiles: the managed
// settings, the user's, and the project's shared and local files.
func claudeSettingsFiles(projectDir string) []SettingsFile {
	var files []SettingsFile
	managed := func(paths ...string) {
		for _, p := range paths {
			files = append(files, SettingsFile{Path: p, Managed: true})
		}
	}
	switch runtime.GOOS {
	case "darwin":
		managed("/Library/Application Support/ClaudeCode/managed-settings.json")
	case "linux":
		managed("/etc/claude-code/managed-settings.json")
		dropins, _ := filepath.Glob("/etc/claude-code/managed-settings.d/*.json")
		managed(dropins...)
	}
	configDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if configDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configDir = filepath.Join(home, ".claude")
		}
	}
	if configDir != "" {
		files = append(files, SettingsFile{Path: filepath.Join(configDir, "settings.json")})
	}
	if projectDir != "" {
		files = append(files,
			SettingsFile{Path: filepath.Join(projectDir, ".claude", "settings.json")},
			SettingsFile{Path: filepath.Join(projectDir, ".claude", "settings.local.json")})
	}
	return files
}
