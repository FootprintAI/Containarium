package server

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// writeFakeTool writes an executable named name in dir that prints out (and, when marker
// is set, also touches it, so a test can tell the tool was executed).
func writeFakeTool(t *testing.T, dir, name, out, marker string) {
	t.Helper()
	body := "#!/bin/sh\n"
	if marker != "" {
		body += "touch '" + marker + "'\n"
	}
	body += "printf '%s\\n' '" + out + "'\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// probeEnv builds a HERMETIC environment for the probe: only the given fake tool
// directories plus symlinks to the plain utilities the probes use. No real git, python3,
// node, make or java is ever executed or even visible (on a developer machine or a CI
// runner those can be slow shims, and their presence would change what a test sees).
func probeEnv(t *testing.T, home string, pathDirs []string) []string {
	t.Helper()
	utils := t.TempDir()
	for _, u := range []string{"head", "tr", "cut", "timeout", "sleep", "date", "touch", "stat", "cksum", "printf", "cat", "sed", "ls", "rm"} {
		if p, err := exec.LookPath(u); err == nil {
			if err := os.Symlink(p, filepath.Join(utils, u)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return []string{"HOME=" + home, "PATH=" + strings.Join(append(append([]string{}, pathDirs...), utils), ":")}
}

func runShell(t *testing.T, env []string, script string) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe failed: %v\n%s\n--- script ---\n%s", err, out, script)
	}
	return string(out)
}

func fields(out string) map[string][]string {
	m := map[string][]string{}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) >= 3 {
			m[f[1]] = f
		}
	}
	return m
}

// The START probe resolves allowlisted tools and fingerprints their binaries, and it EXECUTES
// NOTHING: not the allowlisted tools (a fake one would touch a marker) and not anything else.
// That is what lets it run synchronously before the engine without ever delaying it.
func TestBoxRunToolStartProbe_ExecutesNothing(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "SOMETHING-WAS-EXECUTED")
	writeFakeTool(t, bin, "go", "go version go1.99.0", marker)
	writeFakeTool(t, bin, "buf", "1.99.0", marker)
	writeFakeTool(t, bin, "evil-tool", "pwned", marker) // not on the allowlist

	out := runShell(t, probeEnv(t, root, []string{bin}), boxRunToolStartProbeFn()+"; __probe_start")
	got := fields(out)
	for _, name := range []string{"go", "buf"} {
		f := got[name]
		if len(f) != 3 || f[0] != "S" || f[2] == "" {
			t.Errorf("%s start line = %v, want S / name / fingerprint", name, f)
		}
	}
	if got["evil-tool"] != nil {
		t.Error("the probe reported a tool that is not on the allowlist")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the START probe EXECUTED a binary; it must only resolve and fingerprint")
	}
	if strings.Contains(out, root) {
		t.Errorf("the probe must never print a path:\n%s", out)
	}
}

// The fingerprint tells a replaced or upgraded binary from an unchanged one without running
// it, and is stable across calls.
func TestBoxRunToolStartProbe_FingerprintTracksTheBinary(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, bin, "go", "v1", "")
	if err := exec.Command("stat", "-c", "%s", filepath.Join(bin, "go")).Run(); err != nil {
		t.Skip("this stat has no -c (BSD/macOS): the fingerprint degrades to the path alone here; boxes are Linux")
	}
	env := probeEnv(t, root, []string{bin})
	probe := func() string { return fields(runShell(t, env, boxRunToolStartProbeFn()+"; __probe_start"))["go"][2] }
	a, b := probe(), probe()
	if a != b {
		t.Errorf("the fingerprint must be stable: %q then %q", a, b)
	}
	writeFakeTool(t, bin, "go", "a-much-longer-replacement-version-string", "")
	if c := probe(); c == a {
		t.Error("a replaced binary must change the fingerprint")
	}
}

// The END probe runs each present allowlisted tool's version command, reports the location as a
// class only, and never executes a binary that is not on the allowlist.
func TestBoxRunToolEndProbe_ReportsOnlyTheAllowlistAndNeverRunsAnythingElse(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "runhome")
	homeBin := filepath.Join(home, ".local", "bin")
	sysBin := filepath.Join(root, "sysbin")
	for _, d := range []string{homeBin, sysBin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(root, "EXECUTED-NON-ALLOWLISTED")
	writeFakeTool(t, homeBin, "buf", "1.99.0", "")
	writeFakeTool(t, sysBin, "go", "go version go1.99.0 linux/amd64", "")
	writeFakeTool(t, homeBin, "evil-tool", "pwned", marker)
	writeFakeTool(t, sysBin, "backdoor", "pwned", marker)

	out := runShell(t, probeEnv(t, home, []string{homeBin, sysBin}), boxRunToolEndProbeFn()+"; __probe_end "+shellSingleQuote(filepath.Join(t.TempDir(), "p")))
	got := fields(out)
	if f := got["buf"]; len(f) != 5 || f[0] != "E" || f[2] != "1.99.0" || f[3] != "home" || f[4] == "" {
		t.Errorf("buf line = %v, want E / buf / 1.99.0 / home / fingerprint", f)
	}
	if f := got["go"]; len(f) != 5 || f[2] != "go version go1.99.0 linux/amd64" || f[3] != "system" {
		t.Errorf("go line = %v, want its version and location system", f)
	}
	if got["evil-tool"] != nil || got["backdoor"] != nil {
		t.Errorf("the probe reported a tool that is not on the allowlist: %v", got)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the probe EXECUTED a binary that is not on the allowlist")
	}
	if strings.Contains(out, home) || strings.Contains(out, sysBin) {
		t.Errorf("the probe must report a location class, never a path:\n%s", out)
	}
}

// A tool whose version output is long or full of control characters is reduced to one
// printable, capped line (the value ends up in a public pull request).
func TestBoxRunToolEndProbe_SanitisesTheVersionLine(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("v1.2.3-", 40)
	body := "#!/bin/sh\nprintf '\\033[31m" + long + "\\033[0m\\tTAB\\nsecond line\\n'\n"
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	f := fields(runShell(t, probeEnv(t, root, []string{bin}), boxRunToolEndProbeFn()+"; __probe_end "+shellSingleQuote(filepath.Join(t.TempDir(), "p"))))["node"]
	if len(f) != 5 {
		t.Fatalf("node line = %v, want exactly 5 tab-separated fields", f)
	}
	if len(f[2]) > boxRunToolVersionMax || strings.ContainsAny(f[2], "\x1b\n\t") || strings.Contains(f[2], "second line") {
		t.Errorf("version not sanitised: %q", f[2])
	}
}

// The END probe runs the version commands IN PARALLEL: the exit sidecar waits for it, so its total
// time must be about the slowest tool, not the sum. Three tools that each take 2 s must finish in
// well under the 6 s a sequential run needs (the bound is 5.2 s, to tolerate a loaded runner), and their lines still come out in allowlist order.
func TestBoxRunToolEndProbe_RunsVersionCommandsInParallelAndKeepsTheOrder(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go", "node", "buf"} {
		body := "#!/bin/sh\nsleep 2\necho " + name + "-slow\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	partsDir := t.TempDir()
	start := time.Now()
	out := runShell(t, probeEnv(t, root, []string{bin}), boxRunToolEndProbeFn()+"; __probe_end "+shellSingleQuote(filepath.Join(partsDir, "p")))
	if left, err := os.ReadDir(partsDir); err != nil || len(left) != 0 {
		t.Errorf("the per-tool part files must be removed after the probe, left: %v (%v)", left, err)
	}
	if took := time.Since(start); took > 5200*time.Millisecond {
		t.Errorf("three 2 s tools took %v: the version commands must run in parallel", took)
	}
	var order []string
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 5 {
			order = append(order, f[1]+"="+f[2])
		}
	}
	if got := strings.Join(order, ","); got != "go=go-slow,node=node-slow,buf=buf-slow" {
		t.Errorf("lines must follow the allowlist order with each tool's own version: %q", got)
	}
}

// Without `timeout` nothing is run: a hung tool must never be able to hold a finished run open.
// The tools are still LISTED, with an empty version.
func TestBoxRunToolEndProbe_WithoutTimeoutRunsNoVersionCommandAtAll(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "VERSION-COMMAND-RAN")
	writeFakeTool(t, bin, "go", "go1", marker)
	env := probeEnv(t, root, []string{bin})
	// a utilities directory WITHOUT timeout: rebuild PATH from the one probeEnv made, minus timeout
	utils := strings.Split(strings.TrimPrefix(env[1], "PATH="), ":")[1]
	if err := os.Remove(filepath.Join(utils, "timeout")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	f := fields(runShell(t, env, boxRunToolEndProbeFn()+"; __probe_end "+shellSingleQuote(filepath.Join(t.TempDir(), "p"))))["go"]
	if len(f) != 5 || f[2] != "" {
		t.Errorf("go must be listed with an empty version when there is no timeout: %v", f)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a version command ran although there was no timeout to bound it")
	}
}

func toolsByName(tools []*pb.BoxRunTool) map[string]*pb.BoxRunTool {
	m := map[string]*pb.BoxRunTool{}
	for _, tl := range tools {
		m[tl.GetName()] = tl
	}
	return m
}

func TestParseBoxRunTools_ProvenanceFromTheTwoFingerprints(t *testing.T) {
	sidecar := strings.Join([]string{
		"S\tgo\t111",
		"S\tgit\t222",
		"S\tmake\t333",
		"E\tgo\tgo version go1.26.0\tsystem\t111", // same fingerprint: present at start
		"E\tgit\tgit version 2.50\tsystem\t999",   // different fingerprint: changed
		"E\tmake\tGNU Make 4.3\thome\t444",        // different fingerprint: changed (moved)
		"E\tbuf\t1.75.0\thome\t555",               // not at the start: added
		"E\tnode\tv24.22.1\thome\t666",            // not at the start: added
		"",
	}, "\n")
	got := toolsByName(parseBoxRunTools([]byte(sidecar)))
	want := map[string]pb.BoxRunToolProvenance{
		"go":   pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_PRESENT_AT_START,
		"git":  pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_CHANGED_DURING_RUN,
		"make": pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_CHANGED_DURING_RUN,
		"buf":  pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_ADDED_DURING_RUN,
		"node": pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_ADDED_DURING_RUN,
	}
	for name, prov := range want {
		if got[name] == nil || got[name].GetProvenance() != prov {
			t.Errorf("%s provenance = %v, want %v", name, got[name].GetProvenance(), prov)
		}
	}
	if got["buf"].GetVersion() != "1.75.0" || got["buf"].GetLocation() != pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_HOME {
		t.Errorf("buf = %v", got["buf"])
	}
	if got["go"].GetLocation() != pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_SYSTEM {
		t.Errorf("go location = %v", got["go"].GetLocation())
	}
}

// Only what the END probe saw is reported (what was available at the end), in the allowlist's
// order; and a sidecar a box user could write cannot smuggle in a tool outside the allowlist,
// an oversized or non-ASCII version, or a malformed line.
func TestParseBoxRunTools_IsHardenedAgainstAWritableSidecar(t *testing.T) {
	sidecar := strings.Join([]string{
		"S\tgo\t111", // only at the start: not reported
		"E\tevil\t1.0\tsystem\t1",
		"E\tnode\t" + strings.Repeat("9", 500) + "\thome\t" + strings.Repeat("7", 90),
		"E\tbuf\tvérsion\u202e\x1b[31m\tweird-location\t12ab34",
		"E\tnpm\tonly-four\tfields",
		"X\tmake\t4.3\tsystem\t1",
		"E\tgit\t2.50\tsystem\t1\textra",
	}, "\n")
	got := toolsByName(parseBoxRunTools([]byte(sidecar)))
	if got["go"] != nil || got["evil"] != nil || got["npm"] != nil || got["make"] != nil || got["git"] != nil {
		t.Errorf("tools that must be dropped were reported: %v", got)
	}
	if n := got["node"]; n == nil || len(n.GetVersion()) > boxRunToolVersionMax {
		t.Errorf("node version must be capped at %d, got %v", boxRunToolVersionMax, n)
	}
	b := got["buf"]
	if b == nil || strings.ContainsAny(b.GetVersion(), "\x1bé\u202e") {
		t.Errorf("buf version must be printable ASCII, got %q", b.GetVersion())
	}
	if b.GetLocation() != pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_UNSPECIFIED {
		t.Errorf("an unknown location word must not become a class: %v", b.GetLocation())
	}
	if len(parseBoxRunTools(nil)) != 0 || len(parseBoxRunTools([]byte("garbage with no tabs"))) != 0 {
		t.Error("an empty or garbage sidecar yields no tools")
	}
}

// The wrapper takes the START fingerprint before the engine, the END probe after it, and lands the
// sidecar BEFORE the exit sidecar, so a reader that sees the run finished also sees its tools; the
// tools files of a previous run are cleared at the start and rotated aside with it.
func TestBoxRunSpawnScript_RecordsToolsBeforeTheExitSidecar(t *testing.T) {
	script := boxRunSpawnScript(boxRunSpawn{dir: "/tmp/agent-box", name: "code", command: "ENGINE-COMMAND-MARKER", home: "/srv/x"})
	pre := strings.Index(script, "__probe_start >")
	cmd := strings.Index(script, "ENGINE-COMMAND-MARKER")
	post := strings.Index(script, "__probe_end '")
	move := strings.Index(script, "code.tools")
	exit := strings.Index(script, "code.exit.tmp")
	if pre < 0 || cmd < 0 || post < 0 || exit < 0 || move < 0 {
		t.Fatalf("missing a part of the wrapper (pre=%d cmd=%d post=%d tools=%d exit=%d):\n%s", pre, cmd, post, move, exit, script)
	}
	if pre >= cmd || cmd >= post || post >= exit {
		t.Errorf("order must be start probe, engine, end probe, exit sidecar: pre=%d cmd=%d post=%d exit=%d", pre, cmd, post, exit)
	}
	if !strings.Contains(script, "rm -f '/tmp/agent-box/code.exit'") || !strings.Contains(script, "'/tmp/agent-box/code.tools'") {
		t.Errorf("a new run must clear the previous run's tools sidecar:\n%s", script)
	}
	if !strings.Contains(boxRunRotateScript("/tmp/agent-box", "code", 1790000000), "code.1790000000.tools") {
		t.Error("a finished run's tools sidecar must be rotated aside with it")
	}
	if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
		t.Errorf("the wrapper does not parse as shell: %v\n%s", err, out)
	}
}

// What runs before the engine must not execute any tool: no version command, and none of the
// timeout/budget machinery that only the END probe needs. The engine must never wait for it.
func TestBoxRunSpawnScript_NothingRunsBeforeTheEngineExceptTheFingerprint(t *testing.T) {
	pre := boxRunToolsPreProbe("/tmp/x.tmp")
	for _, banned := range []string{"__to ", "timeout", "--version", "-version", "head -n 1"} {
		if strings.Contains(pre, banned) {
			t.Errorf("the pre-engine probe must not run version commands (found %q):\n%s", banned, pre)
		}
	}
}

// The list script carries the sidecar as one more bounded field, and the parser attaches it to the run;
// a missing or malformed sidecar leaves the run listed with no tools.
func TestParseBoxRunList_AttachesTheToolsSidecar(t *testing.T) {
	rec := `{"version":2,"name":"code","pid":1,"boot_id":"b","command":"x","cwd":"/srv","capture_mode":"combined","log_path":"/l","started_at":"2026-10-23T02:46:29Z"}`
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	tools := "S\tgo\t11\nE\tgo\tgo1.26\tsystem\t11\nE\tbuf\t1.75.0\thome\t22\n"
	for name, tc := range map[string]struct {
		toolsField string
		wantTools  int
	}{
		"present":    {b64(tools), 2},
		"missing":    {"-", 0},
		"not base64": {"%%%", 0},
	} {
		t.Run(name, func(t *testing.T) {
			out := "B b\nP 1\nR code.json " + b64(rec) + " - - - " + tc.toolsField + "\n"
			runs := parseBoxRunList(out, "/tmp/agent-box")
			if len(runs) != 1 || runs[0].GetRunName() != "code" {
				t.Fatalf("the run must still be listed: %v", runs)
			}
			if len(runs[0].GetTools()) != tc.wantTools {
				t.Errorf("tools = %v, want %d", runs[0].GetTools(), tc.wantTools)
			}
		})
	}
	// An old five-field line is not a current list line: both ends ship in one daemon.
	if got := parseBoxRunList("B b\nP 1\nR code.json "+b64(rec)+" - - -\n", "/tmp/agent-box"); len(got) != 0 {
		t.Errorf("a five-field line must be skipped, got %v", got)
	}
}

// A tool's version line that mentions a filesystem path is scrubbed, on the box AND again on the
// daemon: the value ends up in a public pull request and a path can carry the box user's name
// (pip prints where it is installed).
func TestToolVersionLines_NeverCarryAFilesystemPath(t *testing.T) {
	for in, want := range map[string]string{
		"pip 24.0 from /usr/lib/python3/dist-packages/pip (python 3.12)":                  "pip 24.0 (python 3.12)",
		"pip 24.0 from /home/alice/.local/lib/python3.12/site-packages/pip (python 3.12)": "pip 24.0 (python 3.12)",
		"/home/alice/.local/bin/tool 1.2.3":                                               "1.2.3",
		"curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13":                   "curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13",
		"go version go1.26.5 linux/amd64":                                                 "go version go1.26.5 linux/amd64",
		"v24.22.1":                                                                        "v24.22.1",
	} {
		if got := sanitizeToolVersion(in); got != want {
			t.Errorf("sanitizeToolVersion(%q) = %q, want %q", in, got, want)
		}
	}

	// The same on the box: a fake pip that prints a home path must not emit it from the END probe.
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, bin, "pip3", "pip 24.0 from /home/alice/.local/lib/python3.12/site-packages/pip (python 3.12)", "")
	out := runShell(t, probeEnv(t, root, []string{bin}), boxRunToolEndProbeFn()+"; __probe_end "+shellSingleQuote(filepath.Join(t.TempDir(), "p")))
	if strings.Contains(out, "/home/alice") || strings.Contains(out, "site-packages") {
		t.Errorf("the box-side probe leaked a path:\n%s", out)
	}
	if f := fields(out)["pip3"]; len(f) != 5 || f[2] != "pip 24.0 (python 3.12)" {
		t.Errorf("pip3 line = %v, want the version without the path", f)
	}
}
