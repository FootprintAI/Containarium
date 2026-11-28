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
// settings allow all of Bash or the session is in bypassPermissions; a deny
// rule still denies a wrapped command; an ask rule that matches the command
// turns the call into a refusal instead of a prompt. The hook cannot match
// rule patterns the way Claude Code does, so any Bash ask rule leaves
// commands alone. Rules given on the command line (--allowedTools) are not
// visible to a hook; those sessions are not wrapped.

// permissionModeBypass is the mode that approves every call.
const permissionModeBypass = "bypassPermissions"

// blanketBashRules allow every Bash command.
var blanketBashRules = map[string]bool{"Bash": true, "Bash(*)": true}

type claudeSettings struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Ask   []string `json:"ask"`
	} `json:"permissions"`
}

// claudeRunsWrapped says whether Claude Code will run a wrapped Bash command
// in this session rather than refuse it. Every doubt answers no: an
// unwrapped command can leak a failed result, a refused one breaks every
// Bash call.
func (c *call) claudeRunsWrapped() bool {
	project := os.Getenv("CLAUDE_PROJECT_DIR")
	if project == "" {
		project = c.in.CWD
	}
	blanket := c.in.PermissionMode == permissionModeBypass
	for _, path := range c.h.cfg.SettingsFiles(project) {
		raw, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		var s claudeSettings
		if err != nil || json.Unmarshal(raw, &s) != nil {
			// A file Claude Code reads but this hook cannot could hold an
			// ask rule.
			return false
		}
		for _, rule := range s.Permissions.Ask {
			if rule == "Bash" || strings.HasPrefix(rule, "Bash(") {
				return false
			}
		}
		for _, rule := range s.Permissions.Allow {
			if blanketBashRules[rule] {
				blanket = true
			}
		}
	}
	return blanket
}

// claudeSettingsFiles is the default Config.SettingsFiles: the managed
// settings, the user's, and the project's shared and local files.
func claudeSettingsFiles(projectDir string) []string {
	var files []string
	switch runtime.GOOS {
	case "darwin":
		files = append(files, "/Library/Application Support/ClaudeCode/managed-settings.json")
	case "linux":
		files = append(files, "/etc/claude-code/managed-settings.json")
		dropins, _ := filepath.Glob("/etc/claude-code/managed-settings.d/*.json")
		files = append(files, dropins...)
	}
	configDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if configDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configDir = filepath.Join(home, ".claude")
		}
	}
	if configDir != "" {
		files = append(files, filepath.Join(configDir, "settings.json"))
	}
	if projectDir != "" {
		files = append(files,
			filepath.Join(projectDir, ".claude", "settings.json"),
			filepath.Join(projectDir, ".claude", "settings.local.json"))
	}
	return files
}
