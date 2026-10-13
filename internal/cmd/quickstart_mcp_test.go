package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

const wantAgentBoxRemoteCommand = `sh -c 'PATH="$HOME/.local/bin:/usr/local/bin:$PATH" exec agent-box'`

func codexMCPServerFromFile(t *testing.T, path, name string) mcpServerEntry {
	t.Helper()
	var config struct {
		Servers map[string]mcpServerEntry `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(readFile(t, path), &config); err != nil {
		t.Fatalf("parse TOML: %v", err)
	}
	entry, ok := config.Servers[name]
	if !ok {
		t.Fatalf("missing MCP server %q", name)
	}
	return entry
}

func TestQuickstartMCP_NonInteractiveShell(t *testing.T) {
	for _, agent := range supportedAgents {
		t.Run(agent, func(t *testing.T) {
			// A space in HOME also proves the remote shell preserves quoting.
			home := filepath.Join(t.TempDir(), "box home")
			bin := filepath.Join(home, ".local", "bin")
			if err := os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "agent-box"), []byte("#!/bin/sh\nprintf '%s\\n' \"$PATH\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			spec := agentSpecs[agent]
			path := spec.mcpConfigPath(t.TempDir())
			if _, err := spec.wireMCP(path, "containarium-box", "alice"); err != nil {
				t.Fatal(err)
			}
			var entry mcpServerEntry
			if agent == "codex" {
				entry = codexMCPServerFromFile(t, path, "containarium-box")
			} else {
				entry = mcpServerFromFile(t, path, "mcpServers", "containarium-box")
			}
			if entry.Command != "ssh" || len(entry.Args) != 2 || entry.Args[0] != "alice" {
				t.Fatalf("MCP entry = %+v", entry)
			}
			// ssh passes its remote command to a non-interactive shell. Execute
			// that same command with no login files or user-local PATH entry.
			cmd := exec.Command("/bin/sh", "-c", entry.Args[1])
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("remote command failed: %v\n%s", err, out)
			}
			if want := bin + ":/usr/local/bin:/usr/bin:/bin\n"; string(out) != want {
				t.Fatalf("helper PATH = %q, want %q", out, want)
			}
			if entry.Args[1] != wantAgentBoxRemoteCommand {
				t.Fatalf("remote command = %q, want %q", entry.Args[1], wantAgentBoxRemoteCommand)
			}
		})
	}
}

func TestMergeMCPServerJSON_UpgradeLegacy(t *testing.T) {
	for _, tc := range []struct {
		name, entry string
		upgrade     bool
	}{
		{"generated", `{"command":"ssh","args":["alice","agent-box"]}`, true},
		{"extra settings", `{"command":"ssh","args":["alice","agent-box"],"env":{"FOO":"bar"},"timeout":30}`, true},
		{"different host", `{"command":"ssh","args":["bob","agent-box"]}`, false},
		{"custom command", `{"command":"custom","args":["alice","agent-box"]}`, false},
		{"custom flags", `{"command":"ssh","args":["-T","alice","agent-box"]}`, false},
		{"explicit path", `{"command":"ssh","args":["alice","~/.local/bin/agent-box"]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			seed := `{"theme":"dark","mcpServers":{"other":{"command":"foo"},"containarium-box":` + tc.entry + `}}`
			if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			changed, err := mergeMCPServerJSON(path, "mcpServers", "containarium-box", "alice")
			if err != nil || changed != tc.upgrade {
				t.Fatalf("changed = %v, err = %v, want changed = %v", changed, err, tc.upgrade)
			}
			var want, got map[string]any
			if err := json.Unmarshal([]byte(seed), &want); err != nil {
				t.Fatal(err)
			}
			if tc.upgrade {
				want["mcpServers"].(map[string]any)["containarium-box"].(map[string]any)["args"] = []any{"alice", wantAgentBoxRemoteCommand}
			}
			before := readFile(t, path)
			if err := json.Unmarshal([]byte(before), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || (!tc.upgrade && before != seed) {
				t.Fatalf("settings changed unexpectedly:\n%s", before)
			}
			if changed, err := mergeMCPServerJSON(path, "mcpServers", "containarium-box", "alice"); err != nil || changed || readFile(t, path) != before {
				t.Fatalf("second merge must be a no-op: changed = %v, err = %v", changed, err)
			}
		})
	}
}

func TestCodexAppendMCP_UpgradeLegacy(t *testing.T) {
	const header = "[mcp_servers.containarium-box]\n"
	const legacy = "command = \"ssh\"\nargs = [\"alice\", \"agent-box\"]\n"
	for _, tc := range []struct {
		name, entry string
		upgrade     bool
	}{
		{"generated", legacy, true},
		{"extra settings", legacy + "startup_timeout_sec = 30\n", true},
		{"setting before args", strings.Replace(legacy, "args =", "startup_timeout_sec = 30\nargs =", 1), true},
		{"command after args", "args = [\"alice\", \"agent-box\"]\ncommand = \"ssh\"\n", true},
		{"literal strings", "command = 'ssh'\nargs = ['alice', 'agent-box']\n", true},
		{"different host", strings.Replace(legacy, "alice", "bob", 1), false},
		{"custom command", strings.Replace(legacy, "ssh", "custom", 1), false},
		{"custom flags", "command = \"ssh\"\nargs = [\"-T\", \"alice\", \"agent-box\"]\n", false},
		{"explicit path", strings.Replace(legacy, "agent-box", "~/.local/bin/agent-box", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			prefix := "# keep this comment\nmodel = \"o3\"\n\n"
			suffix := "\n[mcp_servers.other]\ncommand = \"foo\"\n"
			seed := prefix + header + tc.entry + suffix
			if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			changed, err := codexAppendMCP(path, "containarium-box", "alice")
			if err != nil || changed != tc.upgrade {
				t.Fatalf("changed = %v, err = %v, want changed = %v", changed, err, tc.upgrade)
			}
			wantEntry := tc.entry
			if tc.upgrade {
				wantEntry = strings.Replace(wantEntry, `"agent-box"`, strconv.Quote(wantAgentBoxRemoteCommand), 1)
				wantEntry = strings.Replace(wantEntry, `'agent-box'`, strconv.Quote(wantAgentBoxRemoteCommand), 1)
			}
			before := readFile(t, path)
			if before != prefix+header+wantEntry+suffix {
				t.Fatalf("config changed unexpectedly:\n%s", before)
			}
			_ = codexMCPServerFromFile(t, path, "containarium-box")
			if changed, err := codexAppendMCP(path, "containarium-box", "alice"); err != nil || changed || readFile(t, path) != before {
				t.Fatalf("second merge must be a no-op: changed = %v, err = %v", changed, err)
			}
		})
	}
}

func TestCodexAppendMCP_PreservesMultilineString(t *testing.T) {
	const prefix = "note = \"\"\"\n[mcp_servers.containarium-box]\ncommand = \"ssh\"\nargs = [\"alice\", \"agent-box\"]\n\"\"\"\n\n[mcp_servers.containarium-box]\n"
	for _, upgrade := range []bool{false, true} {
		t.Run(strconv.FormatBool(upgrade), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			entry := "command = \"custom\"\n"
			if upgrade {
				entry = "command = \"ssh\"\nargs = [\"alice\", \"agent-box\"]\n"
			}
			if err := os.WriteFile(path, []byte(prefix+entry), 0o600); err != nil {
				t.Fatal(err)
			}
			if changed, err := codexAppendMCP(path, "containarium-box", "alice"); err != nil || changed != upgrade {
				t.Fatalf("changed = %v, err = %v, want changed = %v", changed, err, upgrade)
			}
			if upgrade {
				entry = strings.Replace(entry, `"agent-box"`, strconv.Quote(wantAgentBoxRemoteCommand), 1)
			}
			if readFile(t, path) != prefix+entry {
				t.Fatal("TOML multiline string or custom config changed")
			}
		})
	}
}
