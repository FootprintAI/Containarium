package coderun

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// Box-side file access over the session agent-box already holds open (#1727).
//
// `code run` has to do two things before process_start: read the box's
// code.json to learn which engine it was installed with, and write a fresh
// 0600 gateway.env carrying that run's token. Both go through agent-box's
// own read_file / write_file tools on the EXISTING MCP session rather than a
// second ssh invocation.
//
// Two reasons it is write_file and not `shell_exec "printf ... > file"`:
//
//   - The token would otherwise be a shell command argument, which puts it in
//     the box's process table for the life of the call. docs/integrations/pi.md
//     opens by warning against exactly that. write_file carries the content as
//     an MCP argument over the already-encrypted stdio channel instead.
//   - write_file chmods the temp file BEFORE renaming it into place
//     (internal/agentbox/files.go), so the file never exists at its final path
//     with a wider mode. That is the same "umask before the write, not chmod
//     after" property the boxbootstrap apply.sh argues for, and it is why a
//     0600 request here is actually 0600 for the file's whole life.

// GatewayEnvFileMode is the mode a box's gateway.env is written with. A bearer
// token that spends someone's inference budget gets owner-only, always.
const GatewayEnvFileMode = "0600"

// CodeConfigFileMode is the mode code.json is written with (contract C4).
const CodeConfigFileMode = "0600"

// HomeDir returns the box user's home directory.
//
// It exists because agent-box's file tools take real paths — they do not expand
// `~` or `$HOME`, and filepath.Abs resolves a relative path against agent-box's
// own cwd, which is an implementation detail this package should not bet a
// credential's location on. One cheap shell_exec makes every subsequent path
// absolute and explicit. The command carries no secret.
func (s *Session) HomeDir(ctx context.Context) (string, error) {
	text, err := s.callTool(ctx, "shell_exec", map[string]any{
		"command": `printf '%s' "$HOME"`,
	}, true)
	if err != nil {
		return "", fmt.Errorf("resolve $HOME on the box: %w", err)
	}
	// shell_exec frames its reply as key: value plus a stdout section; the
	// home directory is the only non-empty line of that stdout.
	home := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, ":") || strings.Contains(line, ": ") {
			continue
		}
		if strings.HasPrefix(line, "/") {
			home = line
			break
		}
	}
	if home == "" {
		return "", fmt.Errorf("could not read $HOME from the box (shell_exec said: %s)", strings.TrimSpace(text))
	}
	return home, nil
}

// ExpandHome rewrites a "$HOME/..."-rooted path, of the kind the engine package
// embeds in shell scripts, into an absolute path for agent-box's file tools.
//
// The engine package deliberately writes its paths as `$HOME/...` because they
// are mostly interpolated into shell scripts, where the shell expands them.
// The file tools are the one consumer that needs them pre-expanded, so the
// translation lives here rather than duplicating every path as two constants.
func ExpandHome(home, p string) string {
	switch {
	case strings.HasPrefix(p, "$HOME/"):
		return path.Join(home, strings.TrimPrefix(p, "$HOME/"))
	case p == "$HOME":
		return home
	case strings.HasPrefix(p, "~/"):
		return path.Join(home, strings.TrimPrefix(p, "~/"))
	default:
		return p
	}
}

// ReadFile reads absPath from the box.
func (s *Session) ReadFile(ctx context.Context, absPath string) (string, error) {
	text, err := s.callTool(ctx, "read_file", map[string]any{"path": absPath}, true)
	if err != nil {
		return "", fmt.Errorf("read_file %s: %w", absPath, err)
	}
	// read_file frames its reply as a key: value header followed by the
	// content after a marker line, the same convention tail_log uses.
	_, content := parseKV(text, fileContentMarker)
	if content == "" && !strings.Contains(text, fileContentMarker) {
		return "", fmt.Errorf("read_file %s returned no content marker (said: %s)", absPath, strings.TrimSpace(text))
	}
	return content, nil
}

// WriteFile writes content to absPath on the box with mode, atomically.
func (s *Session) WriteFile(ctx context.Context, absPath, content, mode string) error {
	if mode == "" {
		mode = "0644"
	}
	text, err := s.callTool(ctx, "write_file", map[string]any{
		"path":    absPath,
		"content": content,
		"mode":    mode,
	}, true)
	if err != nil {
		return fmt.Errorf("write_file %s: %w", absPath, err)
	}
	// agent-box reports tool-level failures as text, not as a transport
	// error, so an unexamined reply would let a failed write look successful
	// — and a run would then start with no credential at all.
	if !strings.Contains(text, "bytes_written:") {
		return fmt.Errorf("write_file %s did not confirm the write (said: %s)", absPath, strings.TrimSpace(text))
	}
	return nil
}

// fileContentMarker is the separator read_file puts between its header and the
// file's bytes (internal/agentbox/files.go). The trailing newline is part of the
// marker — same as tailLogContentMarker — so the content does not start with a
// stray blank line.
const fileContentMarker = "--- content ---\n"
