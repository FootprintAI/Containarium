// Package toolchain describes the host-managed, shared build tools (#3164).
package toolchain

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HostRoot is also the mount path in a box. Mount the parent, never current:
// switching the host symlink must be visible without replacing the bind mount.
const HostRoot = "/opt/containarium/toolchains"

const DeviceName = "toolchains"

var Tools = []string{"go", "gofmt", "node", "npm", "npx", "pnpm", "buf", "protoc", "staticcheck"}

// Available distinguishes hosts without a toolchain release from installed ones.
func Available(root string) bool {
	info, err := os.Stat(filepath.Join(root, "current", "manifest.json"))
	return err == nil && info.Mode().IsRegular()
}

// CheckRelease reports whether root has a regular current release manifest.
// It preserves Stat errors so callers can distinguish a missing release from
// permission, I/O, and malformed filesystem failures.
func CheckRelease(root string) error {
	path := filepath.Join(root, "current", "manifest.json")
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat managed toolchain manifest %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("managed toolchain manifest %s is not a regular file", path)
	}
	return nil
}

// SetupScript checks the kernel mount state before exposing the tools. A plain
// directory (or an accidentally writable mount) cannot satisfy BUILD_TOOLS.
func SetupScript() string {
	return `set -eu
awk '$2 == "` + HostRoot + `" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }' /proc/mounts || { echo 'missing read-only mount: ` + HostRoot + `' >&2; exit 1; }
` + RuntimeScript(HostRoot) + LinkScript(HostRoot, "/usr/local/bin")
}

// RuntimeScript supplies Node's small OS runtime dependencies on minimal or
// older images. Already-provisioned boxes never call a package manager here.
// This is platform provisioning, before the unprivileged agent is started.
func RuntimeScript(root string) string {
	node := "'" + strings.ReplaceAll(filepath.Join(root, "current/bin/node"), "'", "'\\''") + "'"
	return `set -eu
if ! ` + node + ` --version >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libatomic1 libstdc++6 >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y libatomic libstdc++ >/dev/null
  else
    echo 'managed Node requires the OS runtime libraries libatomic.so.1 and libstdc++.so.6' >&2
    exit 1
  fi
  ` + node + ` --version >/dev/null
fi
`
}

// LinkScript creates only platform-owned links and refuses to replace an
// owner's existing executable. Check all destinations before changing any.
func LinkScript(root, bin string) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	var b strings.Builder
	fmt.Fprintf(&b, "set -eu\nmkdir -p %s\n", q(bin))
	for _, name := range Tools {
		src, dst := filepath.Join(root, "current/bin", name), filepath.Join(bin, name)
		fmt.Fprintf(&b, "[ -x %s ] || { echo 'managed tool %s is missing' >&2; exit 1; }\n", q(src), name)
		fmt.Fprintf(&b, "if [ -e %s ] || [ -L %s ]; then [ \"$(readlink %s)\" = %s ] || { echo 'managed tool conflicts with %s' >&2; exit 1; }; fi\n", q(dst), q(dst), q(dst), q(src), name)
	}
	for _, name := range Tools {
		src, dst := filepath.Join(root, "current/bin", name), filepath.Join(bin, name)
		fmt.Fprintf(&b, "[ \"$(readlink %s)\" = %s ] || ln -sfn %s %s\n", q(dst), q(src), q(src), q(dst))
	}
	return b.String()
}
