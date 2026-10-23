//go:build ebpf_load

package netbpf

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"testing"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Two more routed addresses on the host side of the veth pair, outside the /30
// and distinct from ebpfLoadPeerBoxAddr: one stands in for another tenant's
// box (registered in ip_tenant under a different tenant id), the other for an
// internet destination that is not on the box's egress allow-list.
const (
	ebpfLoadOtherTenantAddr = "10.250.113.1"
	ebpfLoadInternetAddr    = "10.250.114.1"
	ebpfLoadOtherTenant     = uint32(2)
	ebpfLoadEgressModePort  = 8676
)

// TestAttachedProgram_EgressModeSeparatesAllowListFromCrossTenant proves the
// separate egress mode on a real kernel with real TCP: with mode=ENFORCE and
// egress_mode=LOG_ONLY the box cannot reach another tenant's box (the
// cross-tenant drop stays armed) but CAN reach an unlisted internet
// destination (the allow-list miss is only logged). With egress_mode unset the
// same unlisted destination is dropped, exactly as before the field existed.
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
	for _, addr := range []string{ebpfLoadOtherTenantAddr, ebpfLoadInternetAddr} {
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
	setPolicy := func(egressMode pb.NetworkPolicyMode) {
		t.Helper()
		// Empty allow-list: the internet address is an allow-list miss.
		c, err := netpolicy.Compile(&pb.NetworkPolicy{
			Tenant:     "egress-mode-box",
			Mode:       pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
			EgressMode: egressMode,
		})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if err := loader.SetVethPolicy(ifindex, CompileConfig(ebpfLoadTenant, c)); err != nil {
			t.Fatalf("SetVethPolicy: %v", err)
		}
	}
	setPolicy(pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}
	t.Cleanup(func() { _ = loader.DetachVeth(ifindex) })

	boxDial := func(addr string) error {
		script := fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", addr, ebpfLoadEgressModePort)
		out, err := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv, constant script
			"timeout", "3", "bash", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}

	// mode=ENFORCE, egress_mode=LOG_ONLY.
	if err := boxDial(ebpfLoadOtherTenantAddr); err == nil {
		t.Fatal("box -> other tenant connected with mode=ENFORCE, egress_mode=LOG_ONLY; the cross-tenant drop must stay armed")
	}
	if err := boxDial(ebpfLoadInternetAddr); err != nil {
		t.Fatalf("box -> unlisted destination must connect with egress_mode=LOG_ONLY (logged, not dropped): %v", err)
	}

	// egress_mode unset: the allow-list follows mode=ENFORCE again.
	setPolicy(pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED)
	if err := boxDial(ebpfLoadInternetAddr); err == nil {
		t.Fatal("box -> unlisted destination connected with egress_mode unset and mode=ENFORCE; unset must follow mode")
	}
	if err := boxDial(ebpfLoadOtherTenantAddr); err == nil {
		t.Fatal("box -> other tenant connected with mode=ENFORCE")
	}
}
