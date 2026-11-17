//go:build incus

package guardraildropin

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeHookBinary stands in for the pinned binary: it answers the install's
// smoke test the way the real subcommand's help does.
const fakeHookBinary = "#!/bin/sh\necho 'Usage:'\necho '  containarium guardrail hook <event> [flags]'\n"

// The unit tests run against a fake that models links and ownership. This
// runs the same install and check against a real box, where the shell
// scripts, `find -printf`, `runuser`, `timeout` and `mv -T` are the real
// ones, and asserts where root's writes land when the box user has placed
// links in the way (#3762).
func TestIntegrationIncus_GuardrailDropInInstallDoesNotFollowLinks(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}
	name := fmt.Sprintf("gdropin%d-container", os.Getpid())
	if err := client.CreateContainer(incus.ContainerConfig{Name: name, Image: incusenv.BoxImage()}); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { incusenv.DeleteInstance(t, name) })
	if err := client.StartContainer(name); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	sh := func(script string) string {
		t.Helper()
		out, stderr, code, err := client.ExecWithExitCode(name, []string{"sh", "-c", script})
		if err != nil || code != 0 {
			t.Fatalf("in the box: %s\nexit %d, err %v\n%s%s", script, code, err, out, stderr)
		}
		return strings.TrimSpace(out)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, _, code, err := client.ExecWithExitCode(name, []string{"true"}); err == nil && code == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the box never accepted an exec")
		}
		time.Sleep(2 * time.Second)
	}
	const user = "alice"
	sh("useradd -m " + user)

	c, err := newChecker(client, Options{EngineUnit: EngineNone, EngineAddr: EngineNone}.withDefaults(), bytesBinary([]byte(fakeHookBinary)))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := c.current()
	if err != nil {
		t.Fatal(err)
	}

	// A clean install: both files root-owned, and the check passes.
	if err := c.install(name, user); err != nil {
		t.Fatalf("install: %v", err)
	}
	if got := sh("stat -c '%U:%a' " + DropInPath + " " + HookBinaryPath); got != "root:644\nroot:755" {
		t.Fatalf("owner and mode of the installed files:\n%s", got)
	}
	if got := c.check(name, user, cur); got.Coverage != covered || got.ClientInstalled {
		t.Fatalf("after a clean install: %+v", got)
	}

	// A link at each file's own path is replaced, not followed.
	sh("rm -f " + DropInPath + " " + HookBinaryPath + " && ln -s /tmp/redirected-dropin " + DropInPath + " && ln -s /tmp/redirected-binary " + HookBinaryPath)
	if got := c.check(name, user, cur); got.Coverage != tamperedC {
		t.Fatalf("links at the file paths: %+v", got)
	}
	if err := c.install(name, user); err != nil {
		t.Fatalf("install over links: %v", err)
	}
	if got := sh("ls /tmp/redirected-dropin /tmp/redirected-binary 2>/dev/null | wc -l"); got != "0" {
		t.Fatal("a root write followed the box user's link")
	}
	if got := sh("stat -c %F " + DropInPath + " " + HookBinaryPath); got != "regular file\nregular file" {
		t.Fatalf("after install over links:\n%s", got)
	}

	// A managed file whose name holds a newline is still seen, and a FIFO
	// is reported without being opened (opening it would never return).
	sh(`printf '{"disableAllHooks": true}' > "` + DropInDir + `/a
b.json"`)
	if got := c.check(name, user, cur); got.Coverage != tamperedC || !strings.Contains(got.Detail, "disableAllHooks") {
		t.Fatalf("newline in a managed file name: %+v", got)
	}
	sh(`rm -f "` + DropInDir + `/a
b.json" && mkfifo ` + DropInDir + `/pipe.json`)
	if got := c.check(name, user, cur); got.Coverage != tamperedC || !strings.Contains(got.Detail, "cannot be checked") {
		t.Fatalf("a FIFO as a managed file: %+v", got)
	}
	sh("rm -f " + DropInDir + "/pipe.json")

	// A directory replaced by a link is refused, and nothing lands behind it.
	sh("rm -rf " + HookBinaryDir + " && mkdir /tmp/elsewhere && ln -s /tmp/elsewhere " + HookBinaryDir)
	if err := c.install(name, user); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("install into a linked directory: err = %v", err)
	}
	if got := sh("ls -A /tmp/elsewhere | wc -l"); got != "0" {
		t.Fatal("a root write landed behind the linked directory")
	}

	// Removal, the break-glass, works from that state too.
	if err := c.remove(name); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := sh("ls " + DropInPath + " 2>/dev/null | wc -l"); got != "0" {
		t.Fatal("the drop-in survived removal")
	}
}
