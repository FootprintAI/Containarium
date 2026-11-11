package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #3514: `containarium recipe deploy --ssh-key <path>` reads each public-key
// file and sends its contents as ssh_keys, in flag order; an unreadable path
// is a flag error before any RPC.

func writeKeyFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRecipeSSHKeys_ReadsFilesInOrder(t *testing.T) {
	dir := t.TempDir()
	first := writeKeyFile(t, dir, "a.pub", "ssh-ed25519 AAAA first\n")
	second := writeKeyFile(t, dir, "b.pub", "ssh-ed25519 BBBB second\n")

	got, err := recipeSSHKeys([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh-ed25519 AAAA first\n", "ssh-ed25519 BBBB second\n"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("recipeSSHKeys = %q, want %q", got, want)
	}

	if got, err := recipeSSHKeys(nil); err != nil || got != nil {
		t.Errorf("no --ssh-key = (%q, %v), want (nil, nil)", got, err)
	}
}

func TestRecipeSSHKeys_ExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKeyFile(t, home, "id.pub", "ssh-ed25519 AAAA home\n")
	got, err := recipeSSHKeys([]string{"~/id.pub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ssh-ed25519 AAAA home\n" {
		t.Errorf("recipeSSHKeys(~/id.pub) = %q", got)
	}
}

// An unreadable --ssh-key fails before the client is even built: with no
// --server set, the error is the key's, not "--server is required".
func TestRunRecipeDeploy_UnreadableSSHKeyFailsBeforeRPC(t *testing.T) {
	prevKeys, prevServer := recipeDeploySSHKeys, serverAddr
	t.Cleanup(func() { recipeDeploySSHKeys, serverAddr = prevKeys, prevServer })
	missing := filepath.Join(t.TempDir(), "missing.pub")
	recipeDeploySSHKeys = []string{missing}
	serverAddr = ""

	err := runRecipeDeploy(recipeDeployCmd, []string{"plain", "alice"})
	if err == nil || !strings.Contains(err.Error(), "--ssh-key") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("runRecipeDeploy = %v, want a --ssh-key error naming %s", err, missing)
	}
}

func TestRecipeDeployCmd_SSHKeyFlagRepeatable(t *testing.T) {
	f := recipeDeployCmd.Flags().Lookup("ssh-key")
	if f == nil {
		t.Fatal("recipe deploy has no --ssh-key flag")
	}
	if f.Value.Type() != "stringArray" {
		t.Errorf("--ssh-key type = %s, want a repeatable stringArray", f.Value.Type())
	}
}
