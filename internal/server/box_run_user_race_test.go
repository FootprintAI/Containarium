package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The first-use create block in boxRunProvisionScript must tolerate a concurrent
// create: useradd fails with the name in use, but the user exists (#3702).
func provisionCreateBlock(t *testing.T) string {
	t.Helper()
	lines := strings.Split(boxRunProvisionScript(), "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "if ! id -u") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("create block not found")
	}
	end := start
	for end < len(lines) && lines[end] != "fi" {
		end++
	}
	return "set -e\nu=" + boxRunUnprivilegedUser + "\n" + strings.Join(lines[start:end+1], "\n") + "\n"
}

func runCreateBlock(t *testing.T, userExists bool, concurrentCreate bool) error {
	t.Helper()
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "user")
	if userExists {
		if err := os.WriteFile(marker, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// id -u succeeds only once the user exists (the marker).
	if err := os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/bash\n[ -e \"$MARK\" ] && exit 0\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// useradd fails with exit 9 (name in use) and, when simulating a concurrent
	// create, has already created the user.
	useradd := "#!/bin/bash\n"
	if concurrentCreate {
		useradd += "touch \"$MARK\"\n"
	}
	useradd += "exit 9\n"
	if err := os.WriteFile(filepath.Join(bin, "useradd"), []byte(useradd), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", provisionCreateBlock(t))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "MARK="+marker)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("create block output: %s", out)
	}
	return err
}

func TestProvisionCreateToleratesAConcurrentCreate(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	// useradd fails, but another writer created the user meanwhile: succeed.
	if err := runCreateBlock(t, false, true); err != nil {
		t.Fatalf("concurrent create: block failed: %v", err)
	}
	// useradd fails and the user does not exist: still a real failure.
	if err := runCreateBlock(t, false, false); err == nil {
		t.Fatal("a failed useradd with no user present must fail the block")
	}
}
