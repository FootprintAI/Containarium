//go:build ebpf_load

package netbpf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf/perf"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Three more routed addresses on the host side of the veth pair, outside the
// /30 and distinct from ebpfLoadPeerBoxAddr: one stands in for another tenant's
// box (registered in ip_tenant under a different tenant id), one for an
// internet destination that is not on the box's egress allow-list, and the
// cloud metadata address, which the program checks before either of them.
// Binding the metadata address on the host veth shadows the runner's own
// metadata service for the few seconds the test runs; cleanup removes it.
const (
	ebpfLoadOtherTenantAddr = "10.250.113.1"
	ebpfLoadInternetAddr    = "10.250.114.1"
	ebpfLoadMetadataAddr    = "169.254.169.254"
	ebpfLoadOtherTenant     = uint32(2)
	ebpfLoadEgressModePort  = 8676
)

// TestAttachedProgram_EgressModeSeparatesAllowListFromCrossTenant proves the
// separate egress mode on a real kernel with real TCP, for both splits:
//
//   - mode=ENFORCE, egress_mode=LOG_ONLY: the box cannot reach another
//     tenant's box or the metadata address (both follow mode), but CAN reach an
//     unlisted internet destination (the allow-list miss is only logged).
//   - mode=LOG_ONLY, egress_mode=ENFORCE: the unlisted destination is dropped,
//     while the other tenant's box and the metadata address pass (logged).
//   - egress_mode unset: the unlisted destination follows mode=ENFORCE again.
//
// Every would-deny also carries the verdict the program applied (#2970 review),
// read back from the real perf ring, so the daemon can audit a split policy
// from the packet's actual fate.
func TestAttachedProgram_EgressModeSeparatesAllowListFromCrossTenant(t *testing.T) {
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
	for _, addr := range []string{ebpfLoadOtherTenantAddr, ebpfLoadInternetAddr, ebpfLoadMetadataAddr} {
		run("ip", "addr", "add", addr+"/32", "dev", ebpfLoadHostVeth)
		run("ip", "netns", "exec", ebpfLoadNetns, "ip", "route", "add", addr+"/32", "via", ebpfLoadHostAddr)
		t.Cleanup(func() {
			_ = exec.Command("ip", "netns", "exec", ebpfLoadNetns, "ip", "route", "del", addr+"/32").Run() // #nosec G204 -- fixed argv
			_ = exec.Command("ip", "addr", "del", addr+"/32", "dev", ebpfLoadHostVeth).Run()               // #nosec G204 -- fixed argv
		})
		ln, err := net.Listen("tcp4", net.JoinHostPort(addr, fmt.Sprint(ebpfLoadEgressModePort)))
		if err != nil {
			t.Fatalf("listen on %s: %v", addr, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go acceptAndClose(ln)
	}

	// The other tenant's box is a managed container address.
	if err := loader.SetIPTenant(netip.MustParseAddr(ebpfLoadOtherTenantAddr).As4(), ebpfLoadOtherTenant); err != nil {
		t.Fatalf("SetIPTenant: %v", err)
	}
	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}
	setPolicy := func(mode, egressMode pb.NetworkPolicyMode) {
		t.Helper()
		// Empty allow-list: the internet address is an allow-list miss, and the
		// metadata address is not opted in.
		c, err := netpolicy.Compile(&pb.NetworkPolicy{
			Tenant:     "egress-mode-box",
			Mode:       mode,
			EgressMode: egressMode,
		})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if err := loader.SetVethPolicy(ifindex, CompileConfig(ebpfLoadTenant, c)); err != nil {
			t.Fatalf("SetVethPolicy: %v", err)
		}
	}
	const (
		enforce = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
		logOnly = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
		unset   = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED
	)
	setPolicy(enforce, logOnly)
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}
	t.Cleanup(func() { _ = loader.DetachVeth(ifindex) })

	events, err := perf.NewReader(loader.EventsMap(), 4096)
	if err != nil {
		t.Fatalf("perf.NewReader: %v", err)
	}
	t.Cleanup(func() { _ = events.Close() })

	boxDial := func(addr string) error {
		script := fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", addr, ebpfLoadEgressModePort)
		out, err := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv, constant script
			"timeout", "3", "bash", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	// drainEvents discards every deny event already in the ring, so the next
	// verdict read belongs to the dial that follows.
	drainEvents := func() {
		for {
			events.SetDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := events.Read(); err != nil {
				return
			}
		}
	}
	// expect dials addr, checks whether it connected, and checks the verdict
	// the program reported for the dial's would-deny event.
	expect := func(what, addr string, wantConnect bool, wantVerdict uint8) {
		t.Helper()
		drainEvents()
		err := boxDial(addr)
		if wantConnect && err != nil {
			t.Fatalf("%s: box -> %s must connect: %v", what, addr, err)
		}
		if !wantConnect && err == nil {
			t.Fatalf("%s: box -> %s connected; it must be dropped", what, addr)
		}
		dst := netip.MustParseAddr(addr)
		deadline := time.Now().Add(5 * time.Second)
		for {
			events.SetDeadline(deadline)
			rec, err := events.Read()
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("%s: no deny event for box -> %s within 5s", what, addr)
			}
			if err != nil {
				t.Fatalf("%s: read deny event: %v", what, err)
			}
			if rec.LostSamples > 0 || len(rec.RawSample) == 0 {
				continue
			}
			ev, err := ParseDenyEvent(rec.RawSample)
			if err != nil {
				t.Fatalf("%s: ParseDenyEvent: %v", what, err)
			}
			if ev.Dst() != dst {
				continue
			}
			if ev.Verdict != wantVerdict {
				t.Fatalf("%s: deny event for box -> %s carries verdict %d, want %d", what, addr, ev.Verdict, wantVerdict)
			}
			return
		}
	}

	// mode=ENFORCE, egress_mode=LOG_ONLY.
	expect("mode=ENFORCE egress_mode=LOG_ONLY, cross-tenant follows mode", ebpfLoadOtherTenantAddr, false, DenyVerdictDropped)
	expect("mode=ENFORCE egress_mode=LOG_ONLY, metadata follows mode", ebpfLoadMetadataAddr, false, DenyVerdictDropped)
	expect("mode=ENFORCE egress_mode=LOG_ONLY, allow-list miss follows egress_mode", ebpfLoadInternetAddr, true, DenyVerdictLogged)

	// mode=LOG_ONLY, egress_mode=ENFORCE: the reverse split.
	setPolicy(logOnly, enforce)
	expect("mode=LOG_ONLY egress_mode=ENFORCE, allow-list miss follows egress_mode", ebpfLoadInternetAddr, false, DenyVerdictDropped)
	expect("mode=LOG_ONLY egress_mode=ENFORCE, cross-tenant follows mode", ebpfLoadOtherTenantAddr, true, DenyVerdictLogged)
	expect("mode=LOG_ONLY egress_mode=ENFORCE, metadata follows mode", ebpfLoadMetadataAddr, true, DenyVerdictLogged)

	// egress_mode unset: the allow-list follows mode=ENFORCE again.
	setPolicy(enforce, unset)
	expect("mode=ENFORCE egress_mode unset, allow-list miss follows mode", ebpfLoadInternetAddr, false, DenyVerdictDropped)
	expect("mode=ENFORCE egress_mode unset, cross-tenant", ebpfLoadOtherTenantAddr, false, DenyVerdictDropped)
}
