package security

import (
	"context"
	"fmt"
	"log"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/sshdpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Rogue SSH listener detection (#2439).
//
// The sshd posture pass (#2424) keeps the distro sshd key-only, but the box
// owner is root and can start a second SSH server: a hand-built `sshd -f`,
// dropbear, or the stock binary on another port, typically bound to
// loopback and exposed through a reverse tunnel. This check finds those: a
// listening TCP socket held by an SSH-server process that is not the distro
// sshd on a port its sshd_config declares.
//
// Scope, stated plainly: this finds the casual and the accidental. A root
// tenant who renames the binary, or embeds an SSH server in another program,
// is invisible here; stopping that is an egress problem (NetworkPolicy
// ENFORCE). Record-only: a process is the tenant's, so unlike the managed
// drop-in it is never killed or modified.

// listenerProbeTimeout bounds one box's probe so a wedged container cannot
// stall the whole pass.
const listenerProbeTimeout = 30 * time.Second

// maxProbeOutput caps how much of a probe's output is parsed. A box with a
// huge number of descriptors must not turn a 10-minute housekeeping pass
// into a memory problem.
const maxProbeOutput = 4 << 20

// listenerProbeScript prints the box's listening-socket tables, which
// process holds which socket, and each process's executable. It forks a
// handful of times in total (cat, cat, ls, ls) regardless of how many
// processes the box runs, and reads nothing tenant-supplied except what
// those files contain. Output sections are introduced by @-lines.
const listenerProbeScript = `echo @tcp; cat /proc/net/tcp 2>/dev/null
echo @tcp6; cat /proc/net/tcp6 2>/dev/null
echo @fd; ls -l /proc/[0-9]*/fd 2>/dev/null
echo @exe; ls -l /proc/[0-9]*/exe 2>/dev/null
true`

// sshServerBinaries are executable base names that are SSH servers.
var sshServerBinaries = map[string]bool{
	"sshd":          true,
	"dropbear":      true,
	"dropbearmulti": true,
	"tinysshd":      true,
}

// stockSSHDDirs are where the distro's sshd binary lives (merged-/usr and
// split layouts).
var stockSSHDDirs = map[string]bool{"/usr/sbin": true, "/sbin": true}

// listenSocket is one LISTEN row of /proc/net/tcp or tcp6.
type listenSocket struct {
	Port  int
	Bind  string
	Inode string
}

// procSnapshot is one probe's parsed output.
type procSnapshot struct {
	Sockets []listenSocket
	// Owners maps a socket inode to every pid holding a descriptor on it.
	Owners map[string][]int
	// Exes maps a pid to its executable path.
	Exes map[int]string
}

var (
	reSocketFD = regexp.MustCompile(`socket:\[(\d+)\]`)
	reFDHeader = regexp.MustCompile(`^/proc/(\d+)/fd:$`)
	reExeLink  = regexp.MustCompile(`/proc/(\d+)/exe -> (.+)$`)
)

// parseSnapshot parses listenerProbeScript's output. Malformed lines are
// skipped: the input is partly tenant-influenced (paths, names) and a
// parse problem must degrade to "fewer findings", never to a panic.
func parseSnapshot(out string) procSnapshot {
	if len(out) > maxProbeOutput {
		out = out[:maxProbeOutput]
	}
	snap := procSnapshot{Owners: map[string][]int{}, Exes: map[int]string{}}
	section := ""
	curPID := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch line {
		case "@tcp", "@tcp6", "@fd", "@exe":
			section = line
			curPID = 0
			continue
		}
		switch section {
		case "@tcp":
			if s, ok := parseProcNetTCPLine(line, false); ok {
				snap.Sockets = append(snap.Sockets, s)
			}
		case "@tcp6":
			if s, ok := parseProcNetTCPLine(line, true); ok {
				snap.Sockets = append(snap.Sockets, s)
			}
		case "@fd":
			if m := reFDHeader.FindStringSubmatch(line); m != nil {
				curPID, _ = strconv.Atoi(m[1])
				continue
			}
			if curPID == 0 {
				continue
			}
			if m := reSocketFD.FindStringSubmatch(line); m != nil {
				snap.Owners[m[1]] = append(snap.Owners[m[1]], curPID)
			}
		case "@exe":
			if m := reExeLink.FindStringSubmatch(line); m != nil {
				if pid, err := strconv.Atoi(m[1]); err == nil {
					snap.Exes[pid] = m[2]
				}
			}
		}
	}
	return snap
}

// parseProcNetTCPLine parses one /proc/net/tcp{,6} row and keeps only
// sockets in state LISTEN (0A).
//
//	sl  local_address rem_address   st tx_queue:rx_queue ... uid timeout inode
//	0: 0100007F:08AE 00000000:0000 0A 00000000:00000000 ... 0 0 12345 1 ...
func parseProcNetTCPLine(line string, v6 bool) (listenSocket, bool) {
	f := strings.Fields(line)
	if len(f) < 10 || f[3] != "0A" {
		return listenSocket{}, false
	}
	host, portHex, ok := strings.Cut(f[1], ":")
	if !ok {
		return listenSocket{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || port == 0 {
		return listenSocket{}, false
	}
	bind, ok := decodeProcAddr(host, v6)
	if !ok {
		return listenSocket{}, false
	}
	return listenSocket{Port: int(port), Bind: bind, Inode: f[9]}, true
}

// decodeProcAddr turns the kernel's hex address into text. IPv4 is one
// little-endian 32-bit word; IPv6 is four little-endian 32-bit words.
func decodeProcAddr(h string, v6 bool) (string, bool) {
	want := 8
	if v6 {
		want = 32
	}
	if len(h) != want {
		return "", false
	}
	raw := make([]byte, want/2)
	for i := range raw {
		b, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return "", false
		}
		raw[i] = byte(b)
	}
	// Reverse each 4-byte word.
	for w := 0; w+4 <= len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return net.IP(raw).String(), true
}

// cleanBinary makes a tenant-controlled path safe to store and print:
// drops the kernel's " (deleted)" marker (a package upgrade leaves the
// running sshd's binary "deleted" until it restarts, which is not
// suspicious), strips control characters, and bounds the length.
func cleanBinary(p string) string {
	p = strings.TrimSuffix(p, " (deleted)")
	p = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, p)
	if len(p) > 200 {
		p = p[:200]
	}
	return p
}

// rogueListeners returns one entry per SSH-server listener that is not the
// distro sshd on a port its configuration declares. cmdline reports a
// pid's command line (ok=false when unreadable); it is consulted only for
// the stock sshd on a declared port, to catch `sshd -f`/`-o` overrides, and
// an unreadable command line is treated as the managed service so a
// procfs read problem cannot turn into a false alarm.
func rogueListeners(snap procSnapshot, declaredPorts []int, cmdline func(pid int) (string, bool)) []threatdetect.ListenerEvidence {
	declared := map[int]bool{}
	for _, p := range declaredPorts {
		declared[p] = true
	}
	type key struct{ port, pid int }
	seen := map[key]bool{}
	var out []threatdetect.ListenerEvidence
	for _, s := range snap.Sockets {
		for _, pid := range snap.Owners[s.Inode] {
			exe := cleanBinary(snap.Exes[pid])
			if exe == "" || !sshServerBinaries[path.Base(exe)] || seen[key{s.Port, pid}] {
				continue
			}
			note := ""
			switch {
			case path.Base(exe) != "sshd" || !stockSSHDDirs[path.Dir(exe)]:
				note = "not the distro sshd binary"
			case !declared[s.Port]:
				note = "distro sshd on a port its sshd_config does not declare"
			default:
				if cl, ok := cmdline(pid); ok && hasConfigOverride(cl) {
					note = "distro sshd started with its own configuration (-f/-o)"
				}
			}
			if note == "" {
				continue // the managed service
			}
			seen[key{s.Port, pid}] = true
			out = append(out, threatdetect.ListenerEvidence{
				Port: uint32(s.Port), BindAddress: s.Bind, PID: uint32(pid), Binary: exe, Note: note,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].PID < out[j].PID
	})
	return out
}

// hasConfigOverride reports whether an sshd command line (NUL- or
// space-separated) carries -f or -o, alone or inside a flag cluster such as
// -Df, either of which lets it ignore /etc/ssh.
func hasConfigOverride(cmdline string) bool {
	for _, a := range strings.FieldsFunc(cmdline, func(r rune) bool { return r == 0 || r == ' ' }) {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a, "fo") {
			return true
		}
	}
	return false
}

// ReconcileListeners probes one box for SSH servers other than its managed
// sshd and records a HIGH finding when it finds any. It reports how many
// rogue listeners it saw. Independent of ReconcileBox: a box with no
// OpenSSH installed at all (so nothing for the policy pass to do) can
// still be running a dropbear.
func (r *SSHDPostureReconciler) ReconcileListeners(ctx context.Context, name string) (int, error) {
	ports := []int{sshdpolicy.DefaultPort}
	if main, err := r.incus.ReadFile(name, sshdpolicy.MainConfigPath); err == nil {
		ports = sshdpolicy.Ports(sshdpolicy.Merge(string(main), r.readDropIns(name)))
	}

	out, err := r.probe(ctx, name)
	if err != nil {
		return 0, fmt.Errorf("probe listeners: %w", err)
	}
	snap := parseSnapshot(out)
	rogue := rogueListeners(snap, ports, func(pid int) (string, bool) {
		b, err := r.incus.ReadFile(name, "/proc/"+strconv.Itoa(pid)+"/cmdline")
		if err != nil {
			return "", false
		}
		return string(b), true
	})
	if len(rogue) == 0 {
		return 0, nil
	}

	f := &threatdetect.Finding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_BOX_ROGUE_SSH_LISTENER,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
		TenantID:  strings.TrimSuffix(name, "-container"),
		Container: name,
		BackendID: r.getBackendID(),
		Subject:   name,
		Evidence:  threatdetect.Evidence{Listeners: rogue},
		FirstSeen: r.now(),
	}
	if r.sink == nil {
		log.Printf("[sshd-posture] %s: %s (no finding sink configured)", name, describeListeners(rogue))
		return len(rogue), nil
	}
	if _, err := r.sink.Upsert(ctx, f); err != nil {
		return len(rogue), fmt.Errorf("record finding: %w", err)
	}
	log.Printf("[sshd-posture] %s: finding recorded: %s", name, describeListeners(rogue))
	return len(rogue), nil
}

// probe runs the listener script in the box, bounded by listenerProbeTimeout.
func (r *SSHDPostureReconciler) probe(ctx context.Context, name string) (string, error) {
	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		stdout, _, err := r.incus.ExecWithOutput(name, []string{"sh", "-c", listenerProbeScript})
		ch <- result{stdout, err}
	}()
	select {
	case res := <-ch:
		return res.out, res.err
	case <-time.After(listenerProbeTimeout):
		return "", fmt.Errorf("timed out after %v", listenerProbeTimeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func describeListeners(l []threatdetect.ListenerEvidence) string {
	parts := make([]string, 0, len(l))
	for _, e := range l {
		parts = append(parts, fmt.Sprintf("%s:%d pid %d %s (%s)", e.BindAddress, e.Port, e.PID, e.Binary, e.Note))
	}
	return "HIGH: rogue ssh listener " + strings.Join(parts, "; ")
}
