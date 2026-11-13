//go:build ebpf_load

package netbpf

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3709: the per-box outbound connection-rate cap, on a real kernel. The box (a
// netns) opens a burst of TCP connections to an address outside the managed
// set; the program counts the box's new connections (SYN without ACK) in a
// one-second window and, past the cap, drops them under ENFORCE or only counts
// them under LOG_ONLY. Three phases against the same peer, so a failure in the
// enforce phase can only come from the program:
//
//   - uncapped (cap 0): every connection succeeds — the control.
//   - capped, log_only: every connection still succeeds — it counts, never drops.
//   - capped, enforce: connections past the cap fail.
//
// The tenant policy itself stays log_only throughout (an empty allow-list under
// enforce would drop everything and prove nothing about the cap).
const (
	connCapBurst = 12
	connCapRate  = 3
	// The window is a fixed one second, so a burst that straddles a boundary may
	// get the cap twice over. The assertion allows for exactly that and no more.
	connCapMaxConnectedWhenEnforced = 2 * connCapRate
)

// connBurst has the box open n connections in a row and returns how many were
// established. Each attempt gives up quickly: a dropped SYN is retransmitted
// after a second, far longer than the test is willing to wait.
func connBurst(t *testing.T, n int) int {
	t.Helper()
	const script = `
import socket, sys
ok = 0
for _ in range(int(sys.argv[3])):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        s.connect((sys.argv[1], int(sys.argv[2])))
        ok += 1
    except OSError:
        pass
    finally:
        s.close()
print(ok)
`
	out, err := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv, constant script
		"python3", "-c", script, ebpfLoadUnlistedAddr, fmt.Sprint(ebpfLoadUnlistedPort), strconv.Itoa(n)).CombinedOutput()
	if err != nil {
		t.Fatalf("burst from the box: %v\n%s", err, out)
	}
	got, perr := strconv.Atoi(strings.TrimSpace(string(out)))
	if perr != nil {
		t.Fatalf("burst output %q is not a count: %v", out, perr)
	}
	return got
}

func TestAttachedProgram_ConnectionRateCap(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); /* #nosec G204 -- fixed argv */ err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("ip", "addr", "add", ebpfLoadUnlistedAddr+"/32", "dev", ebpfLoadHostVeth)
	run("ip", "netns", "exec", ebpfLoadNetns, "ip", "route", "add", ebpfLoadUnlistedAddr+"/32", "via", ebpfLoadHostAddr)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", ebpfLoadNetns, "ip", "route", "del", ebpfLoadUnlistedAddr+"/32").Run() // #nosec G204 -- fixed argv
		_ = exec.Command("ip", "addr", "del", ebpfLoadUnlistedAddr+"/32", "dev", ebpfLoadHostVeth).Run()               // #nosec G204 -- fixed argv
	})
	ln, err := net.Listen("tcp4", net.JoinHostPort(ebpfLoadUnlistedAddr, fmt.Sprint(ebpfLoadUnlistedPort)))
	if err != nil {
		t.Fatalf("listen on %s: %v", ebpfLoadUnlistedAddr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go acceptAndClose(ln)

	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}
	setCap := func(perSec uint16, mode uint8) {
		t.Helper()
		c, err := netpolicy.Compile(&pb.NetworkPolicy{Tenant: "conn-cap-box", Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		cfg := CompileConfig(ebpfLoadTenant, c)
		cfg.ConnCapPerSec, cfg.ConnCapMode = perSec, mode
		if err := loader.SetVethPolicy(ifindex, cfg); err != nil {
			t.Fatalf("SetVethPolicy: %v", err)
		}
	}
	setCap(0, ModeEnforce) // a mode with no rate is still "no cap"
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}
	t.Cleanup(func() { _ = loader.DetachVeth(ifindex) })

	if got := connBurst(t, connCapBurst); got != connCapBurst {
		t.Fatalf("control (no cap): %d of %d connections succeeded; the probe cannot tell a drop from a failure", got, connCapBurst)
	}

	setCap(connCapRate, ModeLogOnly)
	if got := connBurst(t, connCapBurst); got != connCapBurst {
		t.Errorf("log_only cap %d/s: %d of %d connections succeeded; log_only must count, never drop", connCapRate, got, connCapBurst)
	}

	setCap(connCapRate, ModeEnforce)
	got := connBurst(t, connCapBurst)
	if got > connCapMaxConnectedWhenEnforced {
		t.Errorf("enforce cap %d/s: %d of %d connections succeeded, want at most %d", connCapRate, got, connCapBurst, connCapMaxConnectedWhenEnforced)
	}
	if got == 0 {
		t.Errorf("enforce cap %d/s: no connection succeeded; the cap must let the first %d through", connCapRate, connCapRate)
	}
}
