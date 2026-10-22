package security

import (
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	"github.com/footprintai/containarium/pkg/core/sshdpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// probeOutput builds listenerProbeScript-shaped output. tcp rows are
// "<hexaddr:hexport> <inode>" (state LISTEN), fds are pid -> inodes, exes
// are pid -> binary.
func probeOutput(tcp, tcp6 map[string]string, fds map[int][]string, exes map[int]string) string {
	var b strings.Builder
	row := func(n int, addr, inode string) string {
		return strings.Join([]string{itoa(n) + ":", addr, "00000000:0000", "0A", "00000000:00000000", "00:00000000", "00000000", "0", "0", inode, "1", "0000000000000000", "100", "0", "0", "10", "0"}, " ")
	}
	b.WriteString("@tcp\n   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	n := 0
	for addr, inode := range tcp {
		b.WriteString(row(n, addr, inode) + "\n")
		n++
	}
	b.WriteString("@tcp6\n   sl  local_address rem_address   st\n")
	for addr, inode := range tcp6 {
		b.WriteString(row(n, addr, inode) + "\n")
		n++
	}
	b.WriteString("@fd\n")
	for pid, inodes := range fds {
		b.WriteString("/proc/" + itoa(pid) + "/fd:\ntotal 0\n")
		b.WriteString("lr-x------ 1 root root 64 Oct  9 12:00 0 -> /dev/null\n")
		for i, ino := range inodes {
			b.WriteString("lrwx------ 1 root root 64 Oct  9 12:00 " + itoa(3+i) + " -> socket:[" + ino + "]\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("@exe\n")
	for pid, exe := range exes {
		b.WriteString("lrwxrwxrwx 1 root root 0 Oct  9 12:00 /proc/" + itoa(pid) + "/exe -> " + exe + "\n")
	}
	return b.String()
}

func itoa(n int) string { return strconv.Itoa(n) }

func noCmdline(int) (string, bool) { return "", false }

func TestDecodeProcAddr(t *testing.T) {
	cases := []struct {
		hex  string
		v6   bool
		want string
	}{
		{"0100007F", false, "127.0.0.1"},
		{"00000000", false, "0.0.0.0"},
		{"0A00020F", false, "15.2.0.10"},
		{"00000000000000000000000001000000", true, "::1"},
		{"00000000000000000000000000000000", true, "::"},
	}
	for _, c := range cases {
		got, ok := decodeProcAddr(c.hex, c.v6)
		if !ok || got != c.want {
			t.Errorf("decodeProcAddr(%s,%v) = %q,%v want %q", c.hex, c.v6, got, ok, c.want)
		}
	}
	if _, ok := decodeProcAddr("0100007", false); ok {
		t.Error("short address must not decode")
	}
	if _, ok := decodeProcAddr("ZZZZZZZZ", false); ok {
		t.Error("non-hex address must not decode")
	}
}

func TestParseProcNetTCPLine_OnlyListeners(t *testing.T) {
	listen := "   0: 0100007F:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0"
	s, ok := parseProcNetTCPLine(listen, false)
	if !ok || s.Port != 2222 || s.Bind != "127.0.0.1" || s.Inode != "4242" {
		t.Fatalf("got %+v ok=%v", s, ok)
	}
	established := strings.Replace(listen, " 0A ", " 01 ", 1)
	if _, ok := parseProcNetTCPLine(established, false); ok {
		t.Error("an ESTABLISHED row must be ignored")
	}
	if _, ok := parseProcNetTCPLine("   sl  local_address rem_address   st", false); ok {
		t.Error("the header must be ignored")
	}
}

func TestRogueListeners_Matrix(t *testing.T) {
	const (
		port22   = "00000000:0016" // 0.0.0.0:22
		port2222 = "0100007F:08AE" // 127.0.0.1:2222
		port2200 = "00000000:0898" // 0.0.0.0:2200
		port8080 = "00000000:1F90"
	)
	cases := []struct {
		name     string
		tcp      map[string]string
		fds      map[int][]string
		exes     map[int]string
		declared []int
		cmdline  func(int) (string, bool)
		wantPort []uint32
		wantNote string
	}{
		{
			name: "distro sshd on its declared port is the managed service",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/sbin/sshd"}, declared: []int{22}, cmdline: noCmdline,
		},
		{
			name: "distro sshd whose binary was upgraded underneath it is still the service",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/sbin/sshd (deleted)"}, declared: []int{22}, cmdline: noCmdline,
		},
		{
			name: "split-usr layout /sbin/sshd is also the service",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/sbin/sshd"}, declared: []int{22}, cmdline: noCmdline,
		},
		{
			name: "second sshd on a loopback port is flagged",
			tcp:  map[string]string{port22: "100", port2222: "101"}, fds: map[int][]string{10: {"100"}, 20: {"101"}},
			exes: map[int]string{10: "/usr/sbin/sshd", 20: "/usr/sbin/sshd"}, declared: []int{22}, cmdline: noCmdline,
			wantPort: []uint32{2222}, wantNote: "does not declare",
		},
		{
			name: "a port the config declares is not flagged",
			tcp:  map[string]string{port22: "100", port2200: "101"}, fds: map[int][]string{10: {"100"}, 20: {"101"}},
			exes: map[int]string{10: "/usr/sbin/sshd", 20: "/usr/sbin/sshd"}, declared: []int{22, 2200}, cmdline: noCmdline,
		},
		{
			name: "dropbear is never the distro sshd",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/sbin/dropbear"}, declared: []int{22}, cmdline: noCmdline,
			wantPort: []uint32{22}, wantNote: "not the distro sshd binary",
		},
		{
			name: "an sshd built in /tmp is flagged even on port 22",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/tmp/build/sshd"}, declared: []int{22}, cmdline: noCmdline,
			wantPort: []uint32{22}, wantNote: "not the distro sshd binary",
		},
		{
			name: "stock sshd on a declared port but started with -f is flagged",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/sbin/sshd"}, declared: []int{22},
			cmdline:  func(int) (string, bool) { return "/usr/sbin/sshd\x00-D\x00-f\x00/tmp/x.conf\x00", true },
			wantPort: []uint32{22}, wantNote: "-f/-o",
		},
		{
			name: "stock sshd with an inline -o option is flagged",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/sbin/sshd"}, declared: []int{22},
			cmdline:  func(int) (string, bool) { return "/usr/sbin/sshd -D -o PasswordAuthentication=yes", true },
			wantPort: []uint32{22}, wantNote: "-f/-o",
		},
		{
			name: "an unreadable command line is not an alarm",
			tcp:  map[string]string{port22: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/sbin/sshd"}, declared: []int{22}, cmdline: noCmdline,
		},
		{
			name: "non-ssh listeners are ignored",
			tcp:  map[string]string{port8080: "100"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/bin/python3"}, declared: []int{22}, cmdline: noCmdline,
		},
		{
			name: "a socket whose owner is unknown is ignored, not guessed",
			tcp:  map[string]string{port2222: "999"}, fds: map[int][]string{10: {"100"}},
			exes: map[int]string{10: "/usr/sbin/sshd"}, declared: []int{22}, cmdline: noCmdline,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snap := parseSnapshot(probeOutput(c.tcp, nil, c.fds, c.exes))
			got := rogueListeners(snap, c.declared, c.cmdline)
			if len(got) != len(c.wantPort) {
				t.Fatalf("got %d listeners %+v, want ports %v", len(got), got, c.wantPort)
			}
			for i, p := range c.wantPort {
				if got[i].Port != p {
					t.Errorf("listener %d port = %d, want %d", i, got[i].Port, p)
				}
				if !strings.Contains(got[i].Note, c.wantNote) {
					t.Errorf("note = %q, want it to contain %q", got[i].Note, c.wantNote)
				}
			}
		})
	}
}

func TestRogueListeners_EvidenceFields(t *testing.T) {
	snap := parseSnapshot(probeOutput(map[string]string{"0100007F:08AE": "101"}, nil,
		map[int][]string{20: {"101"}}, map[int]string{20: "/usr/sbin/dropbear"}))
	got := rogueListeners(snap, []int{22}, noCmdline)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	e := got[0]
	if e.Port != 2222 || e.BindAddress != "127.0.0.1" || e.PID != 20 || e.Binary != "/usr/sbin/dropbear" {
		t.Errorf("evidence = %+v", e)
	}
}

func TestRogueListeners_IPv6AndSharedSocket(t *testing.T) {
	// A listener on ::1 and one socket inherited by two pids: one entry per
	// (port, pid), none duplicated.
	snap := parseSnapshot(probeOutput(nil, map[string]string{"00000000000000000000000001000000:08AE": "101"},
		map[int][]string{20: {"101"}, 21: {"101"}}, map[int]string{20: "/usr/sbin/dropbear", 21: "/bin/sh"}))
	got := rogueListeners(snap, []int{22}, noCmdline)
	if len(got) != 1 || got[0].BindAddress != "::1" || got[0].PID != 20 {
		t.Fatalf("got %+v", got)
	}
}

func TestCleanBinary_NeutralisesTenantControlledPaths(t *testing.T) {
	if got := cleanBinary("/usr/sbin/sshd (deleted)"); got != "/usr/sbin/sshd" {
		t.Errorf("deleted marker not stripped: %q", got)
	}
	if got := cleanBinary("/tmp/a\x1b[31m\nb"); strings.ContainsAny(got, "\x1b\n") {
		t.Errorf("control characters survived: %q", got)
	}
	if got := cleanBinary("/" + strings.Repeat("a", 500)); len(got) != 200 {
		t.Errorf("length not bounded: %d", len(got))
	}
}

func TestParseSnapshot_HostileInputDoesNotPanic(t *testing.T) {
	for _, in := range []string{
		"", "@tcp\n@tcp6\n@fd\n@exe\n", "@fd\nlrwx------ 1 root root 64 x 3 -> socket:[5]\n",
		"@tcp\n0: ZZ:ZZ x x\n", "@exe\n/proc/abc/exe -> /x\n", strings.Repeat("@fd\n", 100),
		"@fd\n/proc/99999999999999999999/fd:\nlrwx 3 -> socket:[1]\n",
	} {
		_ = rogueListeners(parseSnapshot(in), []int{22}, noCmdline)
	}
}

// --- ReconcileListeners through the Backend ---

func listenerBox(t *testing.T, probe string, files map[string]string) (*SSHDPostureReconciler, *fakeSink, *incustest.MockBackend) {
	t.Helper()
	box := newFakeBox(files, true)
	m := box.backend()
	m.ExecWithOutputFunc = func(_ string, cmd []string) (string, string, error) {
		if len(cmd) == 3 && cmd[0] == "sh" && cmd[2] == listenerProbeScript {
			return probe, "", nil
		}
		return "", "", nil
	}
	sink := &fakeSink{}
	return NewSSHDPostureReconciler(m, sink, 0), sink, m
}

func TestReconcileListeners_RogueSSHDIsHighAndAttributed(t *testing.T) {
	probe := probeOutput(
		map[string]string{"00000000:0016": "100", "0100007F:08AE": "101"}, nil,
		map[int][]string{10: {"100"}, 20: {"101"}},
		map[int]string{10: "/usr/sbin/sshd", 20: "/usr/sbin/dropbear"})
	r, sink, _ := listenerBox(t, probe, map[string]string{"/etc/ssh/sshd_config": imageDefaultMain})
	r.SetBackendID("backend-a")

	n, err := r.ReconcileListeners(context.Background(), "alice-container")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(sink.findings) != 1 {
		t.Fatalf("findings = %d", len(sink.findings))
	}
	f := sink.findings[0]
	if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_BOX_ROGUE_SSH_LISTENER || f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH {
		t.Errorf("rule/severity = %v/%v", f.Rule, f.Severity)
	}
	if f.TenantID != "alice" || f.Container != "alice-container" || f.Subject != "alice-container" || f.BackendID != "backend-a" {
		t.Errorf("identity = %+v", f)
	}
	if len(f.Evidence.Listeners) != 1 || f.Evidence.Listeners[0].Port != 2222 || f.Evidence.Listeners[0].Binary != "/usr/sbin/dropbear" {
		t.Errorf("evidence = %+v", f.Evidence.Listeners)
	}
}

func TestReconcileListeners_CleanBoxRaisesNothing(t *testing.T) {
	probe := probeOutput(map[string]string{"00000000:0016": "100"}, nil,
		map[int][]string{10: {"100"}}, map[int]string{10: "/usr/sbin/sshd"})
	r, sink, _ := listenerBox(t, probe, map[string]string{"/etc/ssh/sshd_config": imageDefaultMain})
	if n, err := r.ReconcileListeners(context.Background(), "bob-container"); err != nil || n != 0 || len(sink.findings) != 0 {
		t.Fatalf("n=%d err=%v findings=%d", n, err, len(sink.findings))
	}
}

func TestReconcileListeners_DeclaredExtraPortHonoursDropIn(t *testing.T) {
	probe := probeOutput(map[string]string{"00000000:0016": "100", "00000000:0898": "101"}, nil,
		map[int][]string{10: {"100"}, 11: {"101"}}, map[int]string{10: "/usr/sbin/sshd", 11: "/usr/sbin/sshd"})
	files := map[string]string{
		"/etc/ssh/sshd_config":                imageDefaultMain,
		"/etc/ssh/sshd_config.d/20-port.conf": "Port 2200\n",
	}
	r, sink, _ := listenerBox(t, probe, files)
	// Merged config declares 22 (main) and 2200 (drop-in): both are the service.
	if n, err := r.ReconcileListeners(context.Background(), "bob-container"); err != nil || n != 0 || len(sink.findings) != 0 {
		t.Fatalf("n=%d err=%v findings=%d", n, err, len(sink.findings))
	}
}

func TestReconcileListeners_WorksWithoutOpenSSHInstalled(t *testing.T) {
	// No sshd_config at all (minimal image): the policy pass skips the box,
	// but a dropbear on it must still be found.
	probe := probeOutput(map[string]string{"0100007F:08AE": "101"}, nil,
		map[int][]string{20: {"101"}}, map[int]string{20: "/usr/sbin/dropbear"})
	r, sink, _ := listenerBox(t, probe, map[string]string{})
	if n, err := r.ReconcileListeners(context.Background(), "carol-container"); err != nil || n != 1 || len(sink.findings) != 1 {
		t.Fatalf("n=%d err=%v findings=%d", n, err, len(sink.findings))
	}
}

func TestReconcileListeners_NilSinkStillDetects(t *testing.T) {
	probe := probeOutput(map[string]string{"0100007F:08AE": "101"}, nil,
		map[int][]string{20: {"101"}}, map[int]string{20: "/usr/sbin/dropbear"})
	box := newFakeBox(map[string]string{}, true)
	m := box.backend()
	m.ExecWithOutputFunc = func(string, []string) (string, string, error) { return probe, "", nil }
	r := NewSSHDPostureReconciler(m, nil, 0)
	if n, err := r.ReconcileListeners(context.Background(), "d-container"); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestReconcileListeners_ProbeFailureIsAnError(t *testing.T) {
	box := newFakeBox(map[string]string{}, true)
	m := box.backend()
	m.ExecWithOutputFunc = func(string, []string) (string, string, error) { return "", "", context.DeadlineExceeded }
	r := NewSSHDPostureReconciler(m, &fakeSink{}, 0)
	if _, err := r.ReconcileListeners(context.Background(), "e-container"); err == nil {
		t.Fatal("a failed probe must surface, not read as a clean box")
	}
}

func TestReconcileAll_ListenerCheckCountedAndSwitchable(t *testing.T) {
	probe := probeOutput(map[string]string{"0100007F:08AE": "101"}, nil,
		map[int][]string{20: {"101"}}, map[int]string{20: "/usr/sbin/dropbear"})
	build := func() (*SSHDPostureReconciler, *fakeSink) {
		// Compliant box (managed drop-in present) so only the listener check
		// can raise a finding here.
		box := newFakeBox(map[string]string{
			"/etc/ssh/sshd_config": imageDefaultMain,
			sshdpolicy.DropInPath:  string(sshdpolicy.DropInContent()),
		}, true)
		m := box.backend()
		m.ListContainersFunc = func() ([]incus.ContainerInfo, error) {
			return []incus.ContainerInfo{{Name: "f-container", State: "Running"}}, nil
		}
		m.ExecWithOutputFunc = func(string, []string) (string, string, error) { return probe, "", nil }
		s := &fakeSink{}
		return NewSSHDPostureReconciler(m, s, 0), s
	}

	r, sink := build()
	if s := r.ReconcileAll(context.Background()); s.Listeners != 1 || len(sink.findings) != 1 {
		t.Fatalf("summary = %s findings=%d", s, len(sink.findings))
	}

	r, sink = build()
	r.SetListenerCheck(false)
	if s := r.ReconcileAll(context.Background()); s.Listeners != 0 || len(sink.findings) != 0 {
		t.Fatalf("disabled check still ran: %s findings=%d", s, len(sink.findings))
	}
}

// TestProbeScript_RealShell runs the actual probe script in a real shell and
// checks the parser against what the kernel and ls really print, not against
// hand-written fixtures: the test process opens a loopback listener and the
// probe must attribute that socket to this very pid, with this binary.
func TestProbeScript_RealShell(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	out, err := exec.Command("sh", "-c", listenerProbeScript).Output()
	if err != nil {
		t.Fatalf("probe script failed: %v", err)
	}
	snap := parseSnapshot(string(out))

	var sock *listenSocket
	for i := range snap.Sockets {
		if snap.Sockets[i].Port == port {
			sock = &snap.Sockets[i]
		}
	}
	if sock == nil {
		t.Fatalf("listener on port %d not found among %d parsed sockets", port, len(snap.Sockets))
	}
	if sock.Bind != "127.0.0.1" {
		t.Errorf("bind = %q, want 127.0.0.1", sock.Bind)
	}
	owned := false
	for _, pid := range snap.Owners[sock.Inode] {
		if pid == os.Getpid() {
			owned = true
		}
	}
	if !owned {
		t.Fatalf("socket inode %s owners %v do not include this pid %d", sock.Inode, snap.Owners[sock.Inode], os.Getpid())
	}
	self, _ := os.Executable()
	if got := snap.Exes[os.Getpid()]; got != self && cleanBinary(got) != self {
		t.Errorf("exe for own pid = %q, want %q", got, self)
	}
}
