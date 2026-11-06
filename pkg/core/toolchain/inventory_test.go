package toolchain

import (
	"strings"
	"testing"
)

const extraManifest = `{"release":"v1","arch":"amd64","extra_lock_sha256":"abc123","tools":[
 {"name":"go","version":"1.27.3"},
 {"name":"cobol","version":"3.2.0","source":"extra","bin":["bin/cobc","bin/cobcrun"]}]}`

func TestReadInventory(t *testing.T) {
	root := t.TempDir()
	writeRelease(t, root, extraManifest)
	inv, err := ReadInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	if inv.ExtraLockSHA256 != "abc123" || len(inv.Tools) != 2 {
		t.Fatalf("unexpected inventory: %+v", inv)
	}
	if got := inv.Tools[0]; got.Name != "go" || got.Source != SourceManaged {
		t.Errorf("built-in tool should default to %q, got %+v", SourceManaged, got)
	}
	if got := inv.Tools[1]; got.Source != SourceExtra || got.Version != "3.2.0" {
		t.Errorf("extra tool mis-read: %+v", got)
	}
	if got := inv.ExtraExecutables(); strings.Join(got, ",") != "cobc,cobcrun" {
		t.Errorf("ExtraExecutables = %v", got)
	}
}

func TestReadInventoryMissingRelease(t *testing.T) {
	if _, err := ReadInventory(t.TempDir()); err == nil {
		t.Fatal("want an error with no release installed")
	}
}

func TestReadInventoryRejectsUnsafeExtraExecutable(t *testing.T) {
	root := t.TempDir()
	writeRelease(t, root, `{"tools":[{"name":"x","version":"1","source":"extra","bin":["../../bin/sh"]}]}`)
	inv, err := ReadInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.ExtraExecutables(); len(got) != 0 {
		t.Errorf("unsafe name must be dropped, got %v", got)
	}
}

func TestLinkScriptLinksExtraToolsOnlyWhenInstalled(t *testing.T) {
	plain := t.TempDir()
	if s := LinkScript(plain, "/usr/local/bin"); strings.Contains(s, "cobc") {
		t.Error("no manifest: script must only carry built-in tools")
	}
	root := t.TempDir()
	writeRelease(t, root, extraManifest)
	s := LinkScript(root, "/usr/local/bin")
	for _, want := range []string{"/usr/local/bin/cobc", "/usr/local/bin/cobcrun", "managed tool conflicts with cobc"} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q", want)
		}
	}
}
