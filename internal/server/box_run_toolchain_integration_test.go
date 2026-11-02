//go:build incus

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/toolchain"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestIntegrationIncus_ManagedToolchainVolume(t *testing.T) {
	client := incusenv.Require(t)
	// A direct child of /tmp is traversable by an unprivileged container's
	// mapped root; testing.T.TempDir's private parent is deliberately not.
	root, err := os.MkdirTemp("", "ctn-toolchains-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v1", "v2"} {
		bin := filepath.Join(root, version, "bin")
		if err := os.MkdirAll(bin, 0755); err != nil {
			t.Fatal(err)
		}
		for _, tool := range toolchain.Tools {
			if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\necho "+version+"\n"), 0755); err != nil {
				t.Fatal(err)
			}
		}
	}
	activate := func(version string) {
		t.Helper()
		if err := os.Symlink(version, filepath.Join(root, "next")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(root, "next"), filepath.Join(root, "current")); err != nil {
			t.Fatal(err)
		}
	}
	activate("v1")
	for _, lazy := range []bool{false, true} {
		t.Run(fmt.Sprintf("lazy=%v", lazy), func(t *testing.T) {
			name := fmt.Sprintf("toolchains-%d-%v", os.Getpid(), lazy)
			cfg := incus.ContainerConfig{Name: name, Image: incusenv.BoxImage(), Disk: &incus.DiskDevice{Path: "/", Pool: client.StoragePool(), Size: "3GB"}}
			if !lazy {
				cfg.ManagedToolchainRoot = root
			}
			if err := client.CreateContainer(cfg); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { incusenv.DeleteInstance(t, name) })
			if err := client.StartContainer(name); err != nil {
				t.Fatal(err)
			}
			if lazy {
				if err := client.EnsureToolchainVolume(name, root); err != nil {
					t.Fatal(err)
				}
			}
			if err := client.EnsureToolchainVolume(name, root); err != nil {
				t.Fatalf("idempotent mount: %v", err)
			}
			execRoot := func(script string) string {
				t.Helper()
				out, stderr, code, err := client.ExecWithExitCode(name, []string{"sh", "-c", script})
				if err != nil || code != 0 {
					t.Fatalf("box command: %v exit=%d stdout=%s stderr=%s", err, code, out, stderr)
				}
				return out
			}
			execRoot(toolchain.SetupScript() + "\nuseradd -m -s /bin/sh ctn-run\n")
			for _, version := range []string{"v1", "v2", "v1"} {
				activate(version)
				command := ""
				for _, tool := range toolchain.Tools {
					command += tool + " --version; "
				}
				out := execRoot("su -s /bin/sh ctn-run -c " + shellSingleQuote("env -i PATH=/usr/local/bin:/usr/bin:/bin sh -c "+shellSingleQuote(command)))
				if out != strings.Repeat(version+"\n", len(toolchain.Tools)) {
					t.Fatalf("existing box saw %q after switch to %s", out, version)
				}
			}
			_, stderr, code, err := client.ExecWithExitCode(name, []string{"sh", "-c", "LC_ALL=C; export LC_ALL; echo write > " + toolchain.HostRoot + "/write-probe"})
			if err != nil || code == 0 || !strings.Contains(stderr, "Read-only file system") {
				t.Fatalf("kernel must reject a write even as root: exit=%d stderr=%s err=%v", code, stderr, err)
			}
			// Exercise the actual run wrapper's report as the unprivileged user.
			// Boot-time systemd-tmpfiles can still clear /tmp here. Real runs
			// keep their sidecars in the run directory, so use the user's home.
			const reportPath = "/home/ctn-run/managed.tools"
			probe := boxRunToolsPreProbe(reportPath+".tmp") + boxRunToolsPostProbe(reportPath+".tmp", reportPath)
			execRoot("su -s /bin/sh ctn-run -c " + shellSingleQuote(probe))
			tools := parseBoxRunTools([]byte(execRoot("cat " + shellSingleQuote(reportPath))))
			found := map[string]bool{}
			for _, tool := range tools {
				found[tool.GetName()] = true
				if tool.GetProvenance() != pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_PRESENT_AT_START || tool.GetLocation() != pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_SYSTEM {
					t.Fatalf("managed tool provenance: %+v", tool)
				}
			}
			for _, tool := range []string{"go", "node", "npm", "pnpm", "buf", "protoc", "staticcheck"} {
				if !found[tool] {
					t.Errorf("missing tool in wrapper report: %s", tool)
				}
			}
		})
	}
}
