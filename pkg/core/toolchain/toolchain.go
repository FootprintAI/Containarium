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

// SetupScript checks the kernel mount state before exposing the tools. A plain
// directory (or an accidentally writable mount) cannot satisfy BUILD_TOOLS.
func SetupScript() string {
	return `set -eu
awk '$2 == "` + HostRoot + `" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }' /proc/mounts || { echo 'missing read-only mount: ` + HostRoot + `' >&2; exit 1; }
` + LinkScript(HostRoot, "/usr/local/bin")
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
