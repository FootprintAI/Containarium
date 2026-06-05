package container

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// EnvFile describes a dotenv file the daemon delivers into a container for
// docker-compose `env_file:` consumption. Apps running directly in the LXC
// inherit env from the Incus config; nested docker / docker-compose apps do
// NOT, so they reference a file like this via `env_file:` instead.
//
// This is the generalized form of the original OTel-only mechanism (#370).
// Each consumer (OTel monitoring, tenant secrets, …) supplies its own
// path / mode / header; the render + write + remove plumbing is shared.
//
// Deliberately scoped to the dotenv-file delivery target ONLY. The LXC
// config-env path (Manager.SetEnv → environment.<NAME>) has different
// semantics (inherited by LXC processes, visible in `incus config show`)
// and is intentionally NOT folded in here.
type EnvFile struct {
	// Path is the absolute file path inside the container, e.g.
	// "/etc/containarium/otel.env".
	Path string

	// Mode is the octal file mode as a string, e.g. "0644" for
	// non-sensitive values or "0400" for secrets.
	Mode string

	// Header is written verbatim at the top of the file (already
	// including any leading "# " comment markers and a trailing
	// newline). Use it for a "generated, do not edit" banner.
	Header string
}

// RenderEnvFile renders env as a dotenv file: the Header verbatim, then one
// sorted KEY=value line per entry. Pure function so it's trivially testable.
//
// Values are written LITERALLY — there is no escaping. The caller owns the
// contract that values are single-line and free of characters the consuming
// `env_file:` parser can't represent; OTel's values are URLs / IDs / a
// bearer header (no newlines), and the secrets path rejects multi-line
// values at set-time for exactly this reason.
func RenderEnvFile(header string, env map[string]string) []byte {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(header)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(env[k])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// WriteEnvFile renders env and writes it to f.Path inside the container at
// f.Mode, creating the parent directory first (incus file-push doesn't).
// An empty env map is a no-op (nothing to deliver).
func (m *Manager) WriteEnvFile(containerName string, f EnvFile, env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	dir := filepath.Dir(f.Path)
	if err := m.Exec(containerName, []string{"mkdir", "-p", dir}); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := m.WriteFile(containerName, f.Path, RenderEnvFile(f.Header, env), f.Mode); err != nil {
		return fmt.Errorf("write %s: %w", f.Path, err)
	}
	return nil
}

// RemoveEnvFile deletes f.Path inside the container. Used on the
// disable/cleanup path so a stale file doesn't keep feeding values into a
// compose stack after the feature is turned off.
func (m *Manager) RemoveEnvFile(containerName string, f EnvFile) error {
	return m.Exec(containerName, []string{"rm", "-f", f.Path})
}
