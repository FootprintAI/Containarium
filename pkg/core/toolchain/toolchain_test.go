package toolchain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeRuntimeLibrariesAreProvisionedOnlyWhenNeeded(t *testing.T) {
	root, commands := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "current/bin"), 0755); err != nil {
		t.Fatal(err)
	}
	marker, log := filepath.Join(root, "ready"), filepath.Join(root, "installs")
	node := fmt.Sprintf("#!/bin/sh\n[ -f '%s' ]\n", marker)
	if err := os.WriteFile(filepath.Join(root, "current/bin/node"), []byte(node), 0755); err != nil {
		t.Fatal(err)
	}
	apt := fmt.Sprintf("#!/bin/sh\necho \"$*\" >> '%s'\nif [ \"$1\" = install ]; then touch '%s'; fi\n", log, marker)
	if err := os.WriteFile(filepath.Join(commands, "apt-get"), []byte(apt), 0755); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		cmd := exec.Command("sh", "-c", RuntimeScript(root))
		cmd.Env = []string{"PATH=" + commands + ":/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("runtime provisioning: %s %v", out, err)
		}
	}
	data, err := os.ReadFile(log)
	if err != nil || strings.Count(string(data), "\ninstall ") != 1 || !strings.Contains(string(data), "libatomic1 libstdc++6") {
		t.Fatalf("only first setup should install Node libraries: %s %v", data, err)
	}
}

func TestLinksFollowReleaseSwitchAndRollback(t *testing.T) {
	root, bin := t.TempDir(), t.TempDir()
	for _, version := range []string{"v1", "v2"} {
		dir := filepath.Join(root, version, "bin")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for _, tool := range Tools {
			if err := os.WriteFile(filepath.Join(dir, tool), []byte("#!/bin/sh\necho "+version+"\n"), 0755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, version := range []string{"v1", "v2", "v1"} {
		if err := os.Symlink(version, filepath.Join(root, "next")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(root, "next"), filepath.Join(root, "current")); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("sh", "-c", LinkScript(root, bin)).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		// A bare shell has no profiles or developer-specific PATH additions.
		cmd := exec.Command("sh", "-c", "go version; node --version; pnpm --version; protoc --version")
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != strings.Repeat(version+"\n", 4) {
			t.Fatalf("version switch: %s %v", out, err)
		}
	}
}

func TestLinkConflictLeavesOwnerToolUntouched(t *testing.T) {
	root, bin := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "current/bin"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range Tools {
		if err := os.WriteFile(filepath.Join(root, "current/bin", tool), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	ownerTool := filepath.Join(bin, "node")
	if err := os.WriteFile(ownerTool, []byte("owner"), 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-c", LinkScript(root, bin)).CombinedOutput(); err == nil || !strings.Contains(string(out), "conflicts") {
		t.Fatalf("must refuse collision: %s %v", out, err)
	}
	content, err := os.ReadFile(ownerTool)
	if err != nil || string(content) != "owner" {
		t.Fatalf("owner tool overwritten: %s %v", content, err)
	}
	if _, err := os.Lstat(filepath.Join(bin, "go")); !os.IsNotExist(err) {
		t.Fatal("must validate all destinations before exposing tools")
	}
}
