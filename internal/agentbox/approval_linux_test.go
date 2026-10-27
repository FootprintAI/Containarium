//go:build linux

package agentbox

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

const dumpableHelperEnv = "AGENTBOX_TEST_DUMPABLE_HELPER"

// TestDumpableHelper is not a test on its own: TestApprovalServerMemoryIsNotReadable
// re-runs this binary into it as a child process that holds still.
func TestDumpableHelper(t *testing.T) {
	mode := os.Getenv(dumpableHelperEnv)
	if mode == "" {
		t.Skip("helper process for TestApprovalServerMemoryIsNotReadable")
	}
	if mode == "nondumpable" {
		if err := makeNonDumpable(); err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
	}
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(0)
}

// The approval server holds the run's key only in memory. A same-user process
// that can open /proc/<pid>/mem can read it, so the server clears its dumpable
// flag. The control case shows the open succeeds here without that, so the
// refusal is the flag's doing and not this machine's ptrace policy.
func TestApprovalServerMemoryIsNotReadable(t *testing.T) {
	open := func(mode string) error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDumpableHelper$")
		cmd.Env = append(os.Environ(), dumpableHelperEnv+"="+mode)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
		if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
			t.Fatalf("helper (%s) said %q, %v", mode, line, err)
		}
		f, err := os.Open(fmt.Sprintf("/proc/%d/mem", cmd.Process.Pid))
		if err == nil {
			_ = f.Close()
		}
		return err
	}

	if err := open("dumpable"); err != nil {
		t.Skipf("this environment refuses /proc/<pid>/mem of a dumpable child too (%v); nothing to compare against", err)
	}
	if err := open("nondumpable"); err == nil {
		t.Fatal("opened /proc/<pid>/mem of a non-dumpable process as the same user")
	}
}
