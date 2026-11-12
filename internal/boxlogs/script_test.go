package boxlogs

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBox is a directory standing in for a box: Root holds proc/, run/ and
// var/run/ as the script sees them, and bin/ holds fake journalctl, docker
// and systemctl that record their arguments and print canned output.
type fakeBox struct {
	t    *testing.T
	root string
	bin  string
}

func newFakeBox(t *testing.T) *fakeBox {
	t.Helper()
	for _, tool := range []string{"sh", "timeout", "head", "cut", "sed", "date", "grep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
	dir := t.TempDir()
	b := &fakeBox{t: t, root: filepath.Join(dir, "root"), bin: filepath.Join(dir, "bin")}
	for _, d := range []string{"proc/1", "run/user", "var/run", "calls"} {
		if err := os.MkdirAll(filepath.Join(b.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(b.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	b.write("proc/1/comm", "systemd\n")
	return b
}

func (b *fakeBox) write(rel, content string) {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.root, rel), []byte(content), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

// tool installs a fake command: it appends its argv to calls/<name> and runs
// body.
func (b *fakeBox) tool(name, body string) {
	b.t.Helper()
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + filepath.Join(b.root, "calls", name) + "'\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(b.bin, name), []byte(script), 0o755); err != nil {
		b.t.Fatal(err)
	}
}

func (b *fakeBox) calls(name string) string {
	data, _ := os.ReadFile(filepath.Join(b.root, "calls", name))
	return string(data)
}

func (b *fakeBox) socket(rel string) {
	b.t.Helper()
	path := filepath.Join(b.root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		b.t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		b.t.Skipf("cannot make a unix socket at %s: %v", path, err)
	}
	b.t.Cleanup(func() { _ = l.Close() })
}

func (b *fakeBox) run(sp ScriptParams) string {
	b.t.Helper()
	sp.Root = b.root
	cmd := exec.Command("sh", "-c", Script(sp))
	cmd.Env = append(os.Environ(), "PATH="+b.bin+":"+os.Getenv("PATH"))
	cmd.Dir = b.root
	out, err := cmd.Output()
	if err != nil {
		b.t.Fatalf("script: %v\n%s", err, out)
	}
	return string(out)
}

const fakeJournal = `cat <<'EOF'
{"__CURSOR":"s=0123456789abcdef0123456789abcdef;i=1;b=fedcba9876543210fedcba9876543210;m=1;t=1;x=1","__REALTIME_TIMESTAMP":"1762862400000001","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"j1"}
EOF`

func dockerTool(logs string) string {
	return `case "$1" in
--version) echo "Docker version 27.3.1, build ce12230";;
ps) echo "` + testID0 + ` web running";;
logs) ` + logs + `;;
esac`
}

func baseParams() ScriptParams {
	return ScriptParams{ReadJournal: true, ReadContainers: true, Lines: 10, Budget: 3}
}

// Criterion 1 end to end through the real script: one unit and one
// container, both read and both labelled.
func TestScript_DockerBox(t *testing.T) {
	b := newFakeBox(t)
	b.socket("var/run/docker.sock")
	b.tool("journalctl", fakeJournal)
	b.tool("systemctl", `echo "nginx.service loaded active running nginx"`)
	b.tool("docker", dockerTool(`echo "2026-11-11T12:00:00.000002Z GET /"`))

	sp := baseParams()
	sp.JournalCursor = jcur(7)
	sp.ContainerSince = time.Date(2026, 11, 11, 12, 0, 0, 5, time.UTC).UnixNano()
	sp.Units = []string{"nginx.service"}
	out := b.run(sp)
	c, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, out)
	}
	if c.Runtime != pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER {
		t.Fatalf("runtime = %v\n%s", c.Runtime, out)
	}
	if len(c.Journal.Lines) != 1 || c.Journal.Lines[0].Source != "nginx.service" || !c.Journal.Ended || c.Journal.RC != 0 {
		t.Errorf("journal = %+v\n%s", c.Journal, out)
	}
	r := c.ContainerReads[0]
	if r == nil || len(r.Lines) != 1 || r.Lines[0].Source != "web" || r.Lines[0].Text != "GET /" || !r.Ended {
		t.Errorf("container = %+v\n%s", r, out)
	}
	if fmt.Sprint(c.Units) != "[nginx.service]" {
		t.Errorf("units = %v", c.Units)
	}
	jargs := b.calls("journalctl")
	for _, want := range []string{"--after-cursor=" + jcur(7), "-u nginx.service", "-o json"} {
		if !strings.Contains(jargs, want) {
			t.Errorf("journalctl args %q lack %q", jargs, want)
		}
	}
	if dargs := b.calls("docker"); !strings.Contains(dargs, fmt.Sprintf("logs -t --since %d.000000005 %s", sp.ContainerSince/1e9, testID0)) {
		t.Errorf("docker args = %q", dargs)
	}
}

// Criterion 5 through the real script: container names and ids the box
// prints are data, never code, and a 1 MB line is cut in the box.
func TestScript_HostileBox(t *testing.T) {
	b := newFakeBox(t)
	b.socket("var/run/docker.sock")
	pwned := filepath.Join(b.root, "pwned")
	b.tool("journalctl", `head -c 1048576 /dev/zero | tr '\0' 'j'; echo`)
	b.tool("systemctl", `echo "\$(touch `+pwned+`).service x"; echo "a;touch `+pwned+`.service x"`)
	b.tool("docker", `case "$1" in
--version) echo "Docker version 27";;
ps) echo "`+testID0+` \$(touch `+pwned+`) running"; echo "\$(touch `+pwned+`) web running"; echo "`+testID1+` ok running";;
logs) printf '2026-11-11T12:00:00Z '; head -c 1048576 /dev/zero | tr '\0' 'x'; echo; printf '2026-11-11T12:00:01Z \033[2J\377\n';;
esac`)
	out := b.run(baseParams())
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("the script executed text the box printed")
	}
	if len(out) > OutputCap {
		t.Fatalf("output %d bytes over the cap", len(out))
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Units) != 0 {
		t.Errorf("hostile unit names listed: %v", c.Units)
	}
	if len(c.Journal.Lines) != 0 {
		t.Errorf("journal = %+v", c.Journal.Lines)
	}
	// The container with a hostile name is skipped, and the one with a
	// hostile id is never read; the good one's 1 MB line arrives cut.
	var names []string
	for _, ct := range c.Containers {
		names = append(names, ct.Name)
	}
	if fmt.Sprint(names) != "[ok]" {
		t.Errorf("containers = %v", names)
	}
	if strings.Count(b.calls("docker"), "logs") != 1 || strings.Contains(b.calls("docker"), "touch") {
		t.Errorf("docker logs calls = %q", b.calls("docker"))
	}
	var lines []Line
	for _, r := range c.ContainerReads {
		lines = append(lines, r.Lines...)
	}
	if len(lines) != 2 || !lines[0].Truncated || len(lines[0].Text) > TextCap || lines[1].Text != "�[2J�" {
		t.Errorf("lines = %d, first truncated=%v len=%d, second=%q", len(lines), lines[0].Truncated, len(lines[0].Text), lines[len(lines)-1].Text)
	}
}

// The scoping decision: a box whose containers run on podman, or on a
// rootless docker, reports that runtime and reads nothing.
func TestScript_UnsupportedRuntimes(t *testing.T) {
	cases := []struct {
		name  string
		setup func(b *fakeBox)
		want  pb.BoxContainerRuntime
	}{
		{"podman containers running", func(b *fakeBox) {
			b.socket("var/run/docker.sock") // podman-docker's socket
			_ = os.MkdirAll(filepath.Join(b.root, "proc/4242"), 0o755)
			b.write("proc/4242/comm", "conmon\n")
		}, pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_PODMAN},
		{"docker CLI is podman", func(b *fakeBox) {
			b.socket("var/run/docker.sock")
			b.tool("docker", `echo "podman version 4.9.3"`)
		}, pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_PODMAN},
		{"rootless docker", func(b *fakeBox) {
			b.socket("run/user/1000/docker.sock")
		}, pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER_ROOTLESS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeBox(t)
			b.tool("journalctl", fakeJournal)
			b.tool("systemctl", "")
			b.tool("docker", dockerTool(`echo "2026-11-11T12:00:00Z x"`))
			tc.setup(b)
			c, err := Parse(b.run(baseParams()))
			if err != nil {
				t.Fatal(err)
			}
			if c.Runtime != tc.want {
				t.Errorf("runtime = %v, want %v", c.Runtime, tc.want)
			}
			if b.calls("journalctl") != "" || strings.Contains(b.calls("docker"), "logs") {
				t.Errorf("read logs on an unsupported box: journalctl %q docker %q", b.calls("journalctl"), b.calls("docker"))
			}
		})
	}
}

// A box with no container runtime is the journal alone.
func TestScript_NoRuntime(t *testing.T) {
	b := newFakeBox(t)
	b.tool("journalctl", fakeJournal)
	b.tool("systemctl", "")
	b.tool("docker", dockerTool(`echo x`))
	c, err := Parse(b.run(baseParams()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Runtime != pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_NONE || len(c.Journal.Lines) != 1 || b.calls("docker") != "" {
		t.Errorf("runtime %v, journal %d lines, docker calls %q", c.Runtime, len(c.Journal.Lines), b.calls("docker"))
	}
}

// The script times its readers out: a reader that hangs is cut off within
// the budget and its source reported as timed out, not complete.
func TestScript_TimesOut(t *testing.T) {
	b := newFakeBox(t)
	b.tool("journalctl", `echo '{"x":1}'; exec sleep 30`)
	b.tool("systemctl", "")
	sp := baseParams()
	sp.Budget = 1
	start := time.Now()
	c, err := Parse(b.run(sp))
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("script ran %v with a 1s budget", el)
	}
	if c.Journal.RC != 124 && c.Journal.RC != 137 {
		t.Errorf("journal rc = %d, want a timeout", c.Journal.RC)
	}
}

// Only validated values reach the script text.
func TestScript_QuotesOnlyValidatedValues(t *testing.T) {
	s := Script(ScriptParams{ReadJournal: true, JournalCursor: jcur(3), Units: []string{"a.service", "b@x.service"}, Lines: 5, Budget: 2})
	if !strings.Contains(s, "'"+jcur(3)+"'") || !strings.Contains(s, "'a.service b@x.service'") {
		t.Errorf("script does not single-quote the cursor and units:\n%s", s)
	}
	for _, bad := range []ScriptParams{
		{JournalCursor: "x';reboot;'"},
		{Units: []string{"a'b"}},
		{Units: []string{"*"}},
	} {
		if s := Script(bad); strings.Contains(s, "reboot") || strings.Contains(s, "a'b") || strings.Contains(s, "'*'") {
			t.Errorf("an unvalidated value reached the script: %+v", bad)
		}
	}
}
