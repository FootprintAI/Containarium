//go:build incus

package guardraildropin

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// buildStaticClient builds the real client binary, statically linked, the
// way the released one is: the unit the daemon installs runs
// `guardrail engine serve` from it, and the install's smoke test runs
// `guardrail hook --help`.
func buildStaticClient(t *testing.T) openBinary {
	t.Helper()
	out := filepath.Join(t.TempDir(), "containarium")
	build := exec.Command("go", "build", "-tags", "containarium_client", "-o", out, "github.com/footprintai/containarium/cmd/containarium")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the client binary: %v\n%s", err, b)
	}
	return func() (io.ReadSeekCloser, error) { return openHookBinary(out) }
}

// Acceptance for #3767 on a real box with real systemd: with the daemon's
// default flags, enable on a box with no engine ends COVERED with the
// reference engine running as its own non-root service; the box user can
// open the socket through the group, mode 0660; a hook run as the box user
// gets an answer from that engine; disable removes the unit. This is also
// where the unit's hardening directives are proven to start inside an
// Incus system container.
func TestIntegrationIncus_GuardrailBuiltinEngineService(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}
	user := fmt.Sprintf("gengine%d", os.Getpid())
	name := containerName(user)
	if err := client.CreateContainer(incus.ContainerConfig{Name: name, Image: incusenv.BoxImage()}); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { incusenv.DeleteInstance(t, name) })
	if err := client.StartContainer(name); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	try := func(script string) (string, int) {
		t.Helper()
		out, stderr, code, err := client.ExecWithExitCode(name, []string{"sh", "-c", script})
		if err != nil {
			t.Fatalf("in the box: %s\nerr %v\n%s%s", script, err, out, stderr)
		}
		return strings.TrimSpace(out + stderr), code
	}
	sh := func(script string) string {
		t.Helper()
		out, code := try(script)
		if code != 0 {
			t.Fatalf("in the box: %s\nexit %d\n%s", script, code, out)
		}
		return out
	}
	// systemd must be up before a unit can be started.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if out, _, _, err := client.ExecWithExitCode(name, []string{"systemctl", "is-system-running"}); err == nil {
			if s := strings.TrimSpace(out); s == "running" || s == "degraded" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("systemd in the box never finished starting")
		}
		time.Sleep(2 * time.Second)
	}
	sh("useradd -m " + user)

	m, err := newManager(client, client, Options{}, buildStaticClient(t))
	if err != nil {
		t.Fatal(err)
	}
	diagnose := func() string {
		out, _ := try("systemctl status " + ReferenceEngineUnit + " --no-pager; journalctl -u " + ReferenceEngineUnit + " --no-pager -n 40")
		return out
	}

	got, err := m.SetEnabled(user, true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got.Coverage != covered {
		t.Fatalf("after enable: %+v\n%s", got, diagnose())
	}
	if out := sh("systemctl is-active " + ReferenceEngineUnit + "; systemctl is-enabled " + ReferenceEngineUnit); out != "active\nenabled" {
		t.Fatalf("unit state:\n%s", out)
	}
	if out := sh("stat -c '%U:%G:%a' " + ReferenceEngineSocket + " /run/" + referenceRuntimeDir); out != EngineUser+":"+EngineGroup+":660\n"+EngineUser+":"+EngineGroup+":750" {
		t.Fatalf("socket and runtime directory:\n%s", out)
	}
	if out := sh("ps -o user:32= -p \"$(systemctl show -p MainPID --value " + ReferenceEngineUnit + ")\""); strings.TrimSpace(out) != EngineUser {
		t.Fatalf("the engine runs as %q, want %s", out, EngineUser)
	}
	if out := sh("id -nG " + user); !strings.Contains(" "+out+" ", " "+EngineGroup+" ") {
		t.Fatalf("the box user's groups: %s", out)
	}
	if _, code := try("runuser -u nobody -- test -r " + ReferenceEngineSocket); code == 0 {
		t.Fatal("a user outside the group can open the socket")
	}
	// The daemon never touched the name of a separately packaged engine.
	if _, code := try("test -e /etc/systemd/system/containarium-engine.service -o -e /run/containarium-engine"); code == 0 {
		t.Fatal("the daemon wrote under the packaged engine's unit name or socket directory")
	}

	// A hook run as the box user, the way the drop-in runs it: with the
	// engine up the call passes untouched; with it stopped the call is
	// denied. So the answer came from the service, not from in-process rules.
	hook := `printf '%s' '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}' | ` +
		"runuser -u " + user + " -- env -i HOME=/home/" + user + " PATH=/usr/bin:/bin " + HookBinaryPath +
		" guardrail hook PreToolUse --engine-wait 1s --engine " + ReferenceEngineAddr
	if out := sh(hook); out != "" {
		t.Fatalf("with the engine up the hook should pass the call: %s", out)
	}
	sh("systemctl stop " + ReferenceEngineUnit)
	if out := sh(hook); !strings.Contains(out, `"deny"`) {
		t.Fatalf("with the engine stopped the hook should deny: %s", out)
	}
	// The periodic check reports the stopped engine, then starts it again.
	m.tick()
	if got, _ := m.Coverage(user); got.Coverage != engineDown {
		t.Fatalf("with the engine stopped: %+v", got)
	}
	m.tick()
	if got, _ := m.Coverage(user); got.Coverage != covered {
		t.Fatalf("the daemon did not start its engine again: %+v\n%s", got, diagnose())
	}

	if got, err = m.SetEnabled(user, false); err != nil || got.Coverage != featureOff {
		t.Fatalf("disable: %+v, %v", got, err)
	}
	if out := sh("ls " + EngineUnitPath + " " + DropInPath + " " + HookBinaryDir + " " + ReferenceEngineSocket + " 2>/dev/null | wc -l"); out != "0" {
		t.Fatal("something of the install survived disable")
	}
	if out, _ := try("systemctl is-active " + ReferenceEngineUnit); out == "active" {
		t.Fatal("the engine is still running after disable")
	}
	// Documented: the group stays.
	sh("getent group " + EngineGroup)
}
