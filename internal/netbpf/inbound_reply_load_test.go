//go:build ebpf_load

package netbpf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2618: the program runs on the box's host veth TC_INGRESS — every packet the
// box sends — and keeps no connection state, so a box's reply to a connection
// someone else opened (a SYN-ACK, an ICMP echo reply) is judged as if the box
// had opened a new flow. These tests pin both halves of a sound answer on a
// real kernel:
//
//   - TestAttachedProgram_InboundConnectionToEnforcedBox: a peer that connects
//     INTO an enforced box with an empty allow-list gets answered.
//   - TestAttachedProgram_EnforcedBoxEgressStaysJudged: what the box opens
//     itself — a TCP dial, or a forged ACK-only segment carrying a payload,
//     which needs no handshake and so would slip past a "judge only SYNs"
//     rule — is still dropped.
//
// Each phase first runs under log_only as a positive control, so an enforce
// failure can only come from the program.
const (
	// The box's listener (in the netns) for inbound connections.
	ebpfLoadInboundPort = 8678
	// A routed peer on the host side that is not on the box's allow-list, with
	// a TCP listener for the box-initiated dial.
	ebpfLoadUnlistedAddr = "10.250.115.1"
	ebpfLoadUnlistedPort = 8679
)

// setEmptyAllowListPolicy compiles the box policy every phase below uses: no
// egress CIDR, no preset, no metadata opt-in.
func setEmptyAllowListPolicy(t *testing.T, loader *Loader, ifindex int, mode pb.NetworkPolicyMode) {
	t.Helper()
	c, err := netpolicy.Compile(&pb.NetworkPolicy{Tenant: "inbound-reply-box", Mode: mode})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := loader.SetVethPolicy(ifindex, CompileConfig(ebpfLoadTenant, c)); err != nil {
		t.Fatalf("SetVethPolicy: %v", err)
	}
}

func TestAttachedProgram_InboundConnectionToEnforcedBox(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()

	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}
	setEmptyAllowListPolicy(t, loader, ifindex, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}
	// The daemon attaches BOTH hooks (reconcile loop); the egress hook is where
	// a flow opened toward the box is recorded (#2618), so the sender hook can
	// recognise the box's answers. Without it the box's reply is judged as a new
	// outbound flow — which is the very bug under test.
	if err := loader.AttachVethEgress(ifindex); err != nil {
		t.Fatalf("AttachVethEgress: %v", err)
	}
	t.Cleanup(func() { _ = loader.DetachVeth(ifindex) })

	// A service in the box: python3's stdlib HTTP server (on the runner image).
	srv := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv
		"python3", "-m", "http.server", fmt.Sprint(ebpfLoadInboundPort), "--bind", ebpfLoadPeerAddr)
	if err := srv.Start(); err != nil {
		t.Fatalf("start in-netns listener: %v", err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })

	url := fmt.Sprintf("http://%s/", net.JoinHostPort(ebpfLoadPeerAddr, fmt.Sprint(ebpfLoadInboundPort)))
	client := &http.Client{Timeout: 3 * time.Second}
	// httpExchange proves the box's SYN-ACK and its data segments both reached
	// the initiator (the host), not just that a handshake started.
	httpExchange := func() error {
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}
	hostPing := func() error {
		out, err := exec.Command("ping", "-c", "3", "-i", "0.2", "-W", "1", ebpfLoadPeerAddr).CombinedOutput() // #nosec G204 -- fixed argv
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}

	// Positive control (log_only): the listener is up and both probes work.
	var ctrlErr error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ctrlErr = httpExchange(); ctrlErr == nil {
			break
		}
		time.Sleep(200 * time.Millisecond) // listener still starting
	}
	if ctrlErr != nil {
		t.Fatalf("control (log_only): host -> box HTTP exchange failed with nothing enforced: %v", ctrlErr)
	}
	if err := hostPing(); err != nil {
		t.Fatalf("control (log_only): host -> box ping failed with nothing enforced: %v", err)
	}

	// Enforce with the same empty allow-list. The host initiated both flows;
	// the box only answers.
	setEmptyAllowListPolicy(t, loader, ifindex, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE)
	if err := httpExchange(); err != nil {
		t.Errorf("enforce: host -> box HTTP exchange failed — the box's reply was judged as a new outbound flow: %v", err)
	}
	if err := hostPing(); err != nil {
		t.Errorf("enforce: host -> box ping got no echo reply — the box's reply was judged as a new outbound flow: %v", err)
	}
}

// forgeACKScript sends three ACK-only TCP segments (no SYN anywhere, no prior
// connection) carrying argv[5] as payload, from inside the box over a raw
// socket. The box is root in its own netns, so it can always do this.
const forgeACKScript = `
import socket, struct, sys
src, dst, sport, dport, payload = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5].encode()
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff
hdr = struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4, 0x10, 65535, 0, 0)
pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
c = csum(pseudo + hdr + payload)
hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
for _ in range(3):
    s.sendto(hdr + payload, (dst, 0))
`

func TestAttachedProgram_EnforcedBoxEgressStaysJudged(t *testing.T) {
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

	// A raw TCP socket on the unlisted peer sees every TCP segment delivered
	// to it, including ones its TCP stack would reset.
	raw, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(ebpfLoadUnlistedAddr)})
	if err != nil {
		t.Fatalf("raw listen on %s: %v", ebpfLoadUnlistedAddr, err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}
	setEmptyAllowListPolicy(t, loader, ifindex, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}
	t.Cleanup(func() { _ = loader.DetachVeth(ifindex) })

	boxDial := func() error {
		script := fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", ebpfLoadUnlistedAddr, ebpfLoadUnlistedPort)
		out, err := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv, constant script
			"timeout", "3", "bash", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	// forgedACKArrives sends forged ACK-only segments tagged with marker and
	// reports whether any reached the unlisted peer.
	forgedACKArrives := func(marker string) bool {
		t.Helper()
		out, err := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv, constant script
			"python3", "-c", forgeACKScript,
			ebpfLoadPeerAddr, ebpfLoadUnlistedAddr, "40618", fmt.Sprint(ebpfLoadUnlistedPort), marker).CombinedOutput()
		if err != nil {
			t.Fatalf("forge ACK from the box: %v\n%s", err, out)
		}
		buf := make([]byte, 2048)
		deadline := time.Now().Add(2 * time.Second)
		for {
			if err := raw.SetReadDeadline(deadline); err != nil {
				t.Fatalf("raw SetReadDeadline: %v", err)
			}
			n, _, err := raw.ReadFrom(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return false
			}
			if err != nil {
				t.Fatalf("raw read: %v", err)
			}
			if bytes.Contains(buf[:n], []byte(marker)) {
				return true
			}
		}
	}

	// Positive control (log_only): both probes reach the peer, so "did not
	// arrive" under enforce means dropped, not "the probe never worked".
	if err := boxDial(); err != nil {
		t.Fatalf("control (log_only): box -> unlisted peer dial failed with nothing enforced: %v", err)
	}
	if !forgedACKArrives("forged-ack-2618-control") {
		t.Fatal("control (log_only): the forged ACK never reached the unlisted peer with nothing enforced — the probe cannot detect delivery")
	}

	setEmptyAllowListPolicy(t, loader, ifindex, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE)
	if err := boxDial(); err == nil {
		t.Error("enforce: box -> unlisted peer dial connected; a box-initiated flow must stay judged")
	}
	if forgedACKArrives("forged-ack-2618-enforce") {
		t.Error("enforce: a forged ACK-only segment from the box reached an unlisted peer; a packet without a SYN must not open egress")
	}
}

// --- #2618 source-validation guards on a two-veth bridge --------------------
//
// Addresses, all distinct from the single-pair fixture TestMain builds
// (10.250.111.x) and the other load tests.
const (
	spoofBridge   = "ebpfload-br"
	spoofAHostV   = "ebpfload-ah" // abox host veth (on the bridge)
	spoofAPeerV   = "ebpfload-ap"
	spoofANetns   = "ebpfload-ans"
	spoofNHostV   = "ebpfload-nh" // neighbour box host veth
	spoofNPeerV   = "ebpfload-np"
	spoofNNetns   = "ebpfload-nns"
	spoofBridgeIP = "10.251.0.1"
	spoofAAddr    = "10.251.0.2"
	spoofNAddr    = "10.251.0.3"
	spoofSubnet   = "/24"
	spoofTenantA  = uint32(11)
	spoofTenantN  = uint32(12)
	// P: an external address the host owns, so a raw socket on it receives. The
	// neighbour forges a SYN "from" P so a seed, if planted, matches abox's exfil.
	spoofExfilAddr = "10.251.9.9"
	spoofExfilPort = 9999
	spoofBoxPort   = 7777 // abox's source port on the forged tuple = the forged SYN's dport
	// Distinct ports for the positive control, so its (valid) seed is a
	// different map entry and cannot mask the negative assertion.
	spoofCtrlExfilPort = 9998
	spoofCtrlBoxPort   = 7778
)

// forgeSYNScript sends N TCP SYN segments (no ACK) with a FORGED source address,
// building the whole IP header so the kernel does not overwrite the source with
// the netns's own address (IP_HDRINCL). A box is root in its own netns, so it
// can spoof any source — which is exactly what source validation has to stop.
// argv: src dst sport dport count.
const forgeSYNScript = `
import socket, struct, sys
src, dst, sport, dport, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff
tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)  # SYN only
pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                 socket.inet_aton(src), socket.inet_aton(dst))
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for _ in range(count):
    s.sendto(ip + tcp, (dst, 0))
`

// spoofBridgeSetup builds the two-veth bridge (abox + neighbour nbox) and P on
// the host, attaches both hooks, and returns abox's ifindex, a raw reader on P,
// and setBox. The neighbour's mode is the caller's (log_only is the worst case:
// its own hook only logs its forgery, so only abox's receiving-side check stops
// the seed). abox is always enforce with an empty allow-list.
type spoofTopo struct {
	aIf, nIf int
	raw      *net.IPConn
}

// cleanSpoofIfaces best-effort removes every interface and netns the spoof and
// routed topologies use. Deleting a bridge only unenslaves its ports — the
// host-side veths survive — and a leaked run (a failed setup, or a re-run on the
// same machine) must not fail the next test, so both setup and teardown call
// this to stay order-independent.
func cleanSpoofIfaces() {
	for _, l := range []string{spoofBridge, spoofAHostV, spoofNHostV, routedNHostV, routedPHostV, strayHostV} {
		_ = exec.Command("ip", "link", "delete", l).Run() // #nosec G204 -- fixed argv
	}
	for _, n := range []string{spoofANetns, spoofNNetns, routedNNetns, routedPNetns, strayNetns} {
		_ = exec.Command("ip", "netns", "delete", n).Run() // #nosec G204 -- fixed argv
	}
}

func setupSpoofBridge(t *testing.T, loader *Loader, nbox pb.NetworkPolicyMode) spoofTopo {
	t.Helper()
	cleanSpoofIfaces()
	t.Cleanup(cleanSpoofIfaces)
	run := func(args ...string) {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); /* #nosec G204 -- fixed argv */ err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("ip", "link", "add", spoofBridge, "type", "bridge")
	run("ip", "addr", "add", spoofBridgeIP+spoofSubnet, "dev", spoofBridge)
	run("ip", "link", "set", spoofBridge, "up")
	run("sysctl", "-wq", "net.ipv4.ip_forward=1")
	for _, b := range []struct{ hostV, peerV, netns, addr string }{
		{spoofAHostV, spoofAPeerV, spoofANetns, spoofAAddr},
		{spoofNHostV, spoofNPeerV, spoofNNetns, spoofNAddr},
	} {
		run("ip", "netns", "add", b.netns)
		run("ip", "link", "add", b.hostV, "type", "veth", "peer", "name", b.peerV)
		run("ip", "link", "set", b.hostV, "master", spoofBridge)
		run("ip", "link", "set", b.hostV, "up")
		run("ip", "link", "set", b.peerV, "netns", b.netns)
		run("ip", "netns", "exec", b.netns, "ip", "addr", "add", b.addr+spoofSubnet, "dev", b.peerV)
		run("ip", "netns", "exec", b.netns, "ip", "link", "set", b.peerV, "up")
		run("ip", "netns", "exec", b.netns, "ip", "link", "set", "lo", "up")
		run("ip", "netns", "exec", b.netns, "ip", "route", "add", "default", "via", spoofBridgeIP)
	}
	t.Cleanup(func() {
		for _, ns := range []string{spoofANetns, spoofNNetns} {
			_ = exec.Command("ip", "netns", "delete", ns).Run() // #nosec G204 -- fixed argv
		}
		_ = exec.Command("ip", "link", "delete", spoofBridge).Run() // #nosec G204 -- fixed argv
	})
	run("ip", "addr", "add", spoofExfilAddr+"/32", "dev", spoofBridge)
	t.Cleanup(func() {
		_ = exec.Command("ip", "addr", "del", spoofExfilAddr+"/32", "dev", spoofBridge).Run() // #nosec G204 -- fixed argv
	})
	raw, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(spoofExfilAddr)})
	if err != nil {
		t.Fatalf("raw listen on P %s: %v", spoofExfilAddr, err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	aIf, err := VethIndex(spoofAHostV)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", spoofAHostV, err)
	}
	nIf, err := VethIndex(spoofNHostV)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", spoofNHostV, err)
	}
	setBox := func(ifindex int, tenant uint32, addr string, mode pb.NetworkPolicyMode) {
		c, err := netpolicy.Compile(&pb.NetworkPolicy{Tenant: fmt.Sprintf("spoof-%d", tenant), Mode: mode})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		cfg := CompileConfig(tenant, c)
		ip4 := net.ParseIP(addr).To4()
		if ip4 == nil {
			t.Fatalf("not IPv4: %q", addr)
		}
		copy(cfg.BoxIP[:], ip4)
		if err := loader.SetVethPolicy(ifindex, cfg); err != nil {
			t.Fatalf("SetVethPolicy: %v", err)
		}
	}
	setBox(aIf, spoofTenantA, spoofAAddr, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE)
	setBox(nIf, spoofTenantN, spoofNAddr, nbox)
	for _, idx := range []int{aIf, nIf} {
		if err := loader.AttachVeth(idx); err != nil {
			t.Fatalf("AttachVeth(%d): %v", idx, err)
		}
		if err := loader.AttachVethEgress(idx); err != nil {
			t.Fatalf("AttachVethEgress(%d): %v", idx, err)
		}
		t.Cleanup(func() { _ = loader.DetachVeth(idx) })
	}
	return spoofTopo{aIf: aIf, nIf: nIf, raw: raw}
}

// aboxExfil sends ACK-only segments abox -> P:dstPort from srcPort, tagged with
// marker, and reports whether any reached P's raw socket. An ACK is not a fresh
// SYN, so it is exactly the segment inbound_reply would wave through on a seeded
// flow — the channel #3070's forged-ACK finding identified.
func aboxExfil(t *testing.T, raw *net.IPConn, srcPort, dstPort int, marker string) bool {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", spoofANetns, // #nosec G204 -- fixed argv, constant script
		"python3", "-c", forgeACKScript,
		spoofAAddr, spoofExfilAddr, fmt.Sprint(srcPort), fmt.Sprint(dstPort), marker).CombinedOutput()
	if err != nil {
		t.Fatalf("send ACK from abox: %v\n%s", err, out)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := raw.SetReadDeadline(deadline); err != nil {
			t.Fatalf("raw SetReadDeadline: %v", err)
		}
		n, _, err := raw.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false
		}
		if err != nil {
			t.Fatalf("raw read: %v", err)
		}
		if bytes.Contains(buf[:n], []byte(marker)) {
			return true
		}
	}
}

// forgeSYNToAbox sends forged SYNs src:sport -> abox:dport from the named netns
// (or the host when netns==""), then waits for them to reach abox's egress hook.
func forgeSYNToAbox(t *testing.T, netns, src string, sport, dport int) {
	t.Helper()
	args := []string{"python3", "-c", forgeSYNScript, src, spoofAAddr, fmt.Sprint(sport), fmt.Sprint(dport), "5"}
	if netns != "" {
		args = append([]string{"ip", "netns", "exec", netns}, args...)
	}
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil { // #nosec G204 -- fixed argv, constant script
		t.Fatalf("forge SYN (netns=%q src=%s): %v\n%s", netns, src, err, out)
	}
	time.Sleep(300 * time.Millisecond) // traverse the bridge to abox's egress hook
}

// TestAttachedProgram_SpoofedInboundSeedDoesNotOpenEgress is the source-validation
// guard (#2618 decision, option (a)) on a real kernel. A log_only neighbour nbox
// forges a SYN from an external address P into the enforced abox. A positive
// control first proves a VALIDLY seeded flow DOES open egress on this topology,
// so the negative result is "the seed was rejected", not "seeding never works".
//
// Mutation guard: remove the mark-based source check in track_inbound and the
// forged seed is trusted, the exfil ACK reaches P, and this test fails.
func TestAttachedProgram_SpoofedInboundSeedDoesNotOpenEgress(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()
	if !loader.SupportsInboundReplies() {
		t.Fatal("loaded object has no inbound-flow/box_ip support — rebuild netpolicy.bpf.o for #2618")
	}
	br := setupSpoofBridge(t, loader, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)

	// Precondition: with no seed, abox's ACK to P is dropped (empty allow-list,
	// enforce). If it already reached P, the rest proves nothing.
	if aboxExfil(t, br.raw, spoofBoxPort, spoofExfilPort, "spoof-2618-baseline") {
		t.Fatal("precondition: abox reached P under enforce with no seed — enforcement is not active")
	}

	// POSITIVE CONTROL (#2618 B3): a VALID seed opens egress on this exact
	// topology. The host owns P and opens a flow from P to abox:spoofCtrlBoxPort
	// — a host-originated frame carries no managed-veth mark, so it is trusted
	// and seeds. abox's ACK to P:spoofCtrlExfilPort on that tuple then arrives.
	// Distinct ports from the negative, so this seed is a different map entry.
	forgeSYNToAbox(t, "", spoofExfilAddr, spoofCtrlExfilPort, spoofCtrlBoxPort)
	if !aboxExfil(t, br.raw, spoofCtrlBoxPort, spoofCtrlExfilPort, "spoof-2618-valid-seed") {
		t.Fatal("positive control: abox did not reach P after a VALID host-originated seed — seeding/reply is broken on this topology, so the negative result below would prove nothing")
	}

	// NEGATIVE: nbox (log_only) forges a SYN FROM P. Its own hook only logs the
	// forgery; only abox's receiving-side mark check withholds the seed.
	forgeSYNToAbox(t, spoofNNetns, spoofExfilAddr, spoofExfilPort, spoofBoxPort)
	if aboxExfil(t, br.raw, spoofBoxPort, spoofExfilPort, "spoof-2618-after-forged-seed") {
		t.Error("a neighbour's forged SYN from an external address opened the enforced box's egress — source validation (#2618) is not holding")
	}
}

// TestAttachedProgram_NoPolicyNeighbourCannotSeedForgery is the B2 "unmanaged /
// no-policy container" branch: the neighbour has a VALIDATE-ONLY entry (what
// gather now gives an instance with no tenant), not a tenant policy. Its sender
// hook still marks its frames, so its forgery from P is still withheld. abox
// must not reach P. (Combined with the log_only neighbour above, both of B2's
// named neighbour cases are covered.)
func TestAttachedProgram_NoPolicyNeighbourCannotSeedForgery(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()
	if !loader.SupportsInboundReplies() {
		t.Fatal("loaded object has no inbound-flow/box_ip support — rebuild netpolicy.bpf.o for #2618")
	}
	// log_only for the shared setup, then overwrite nbox with a validate-only
	// entry: not a tenant, source-validation marking only.
	br := setupSpoofBridge(t, loader, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)
	if err := loader.SetVethPolicy(br.nIf, ValidateOnlyConfig([4]byte{10, 251, 0, 3})); err != nil {
		t.Fatalf("SetVethPolicy(validate-only): %v", err)
	}

	if aboxExfil(t, br.raw, spoofBoxPort, spoofExfilPort, "nopol-2618-baseline") {
		t.Fatal("precondition: abox reached P with no seed under enforce — enforcement is not active")
	}
	forgeSYNToAbox(t, spoofNNetns, spoofExfilAddr, spoofExfilPort, spoofBoxPort)
	if aboxExfil(t, br.raw, spoofBoxPort, spoofExfilPort, "nopol-2618-after-forged-seed") {
		t.Error("a validate-only (no-policy) neighbour's forged SYN opened the enforced box's egress — the mark is not set for an unpoliced instance (#2618 B2)")
	}
	// Control: the SAME validate-only neighbour, sending from its OWN address,
	// seeds a flow abox may answer — abox's ACK on the reverse tuple arrives in
	// nbox's namespace. This proves the neighbour's own VALIDATED path works, so
	// the forgery above was withheld by the mark, not by a broken topology.
	if !aboxAnswersPeer(t, spoofNNetns, spoofNAddr, spoofCtrlBoxPort, spoofCtrlExfilPort, "nopol-2618-own-address") {
		t.Fatal("positive control: abox's answer to the validate-only neighbour's OWN-address seed did not arrive — the neighbour's validated path is broken")
	}
}

// sniffScript listens on a raw TCP socket inside the current netns and prints
// HIT when a segment carrying argv[1] arrives before the deadline (argv[2]
// seconds), else MISS. It prints READY once the socket is open so the caller can
// start sending. argv: marker seconds
const sniffScript = `
import socket, sys, time
marker, secs = sys.argv[1].encode(), float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.settimeout(0.2)
print("READY", flush=True)
end = time.monotonic() + secs
while time.monotonic() < end:
    try:
        data = s.recv(65535)
    except socket.timeout:
        continue
    if marker in data:
        print("HIT", flush=True)
        sys.exit(0)
print("MISS", flush=True)
sys.exit(1)
`

// sniffInNetns starts a raw TCP sniffer in netns, waits until it is listening,
// runs send, and reports whether a segment with marker arrived within 2s.
func sniffInNetns(t *testing.T, netns, marker string, send func()) bool {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", netns, "python3", "-c", sniffScript, marker, "2") // #nosec G204 -- fixed argv, constant script
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("sniffer stdout: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sniffer in %s: %v", netns, err)
	}
	rd := bufio.NewReader(stdout)
	line, err := rd.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "READY") {
		_ = cmd.Process.Kill()
		t.Fatalf("sniffer in %s did not report READY: %q %v", netns, line, err)
	}
	send()
	verdict, _ := rd.ReadString('\n')
	_ = cmd.Wait()
	return strings.HasPrefix(verdict, "HIT")
}

// aboxAnswersPeer is the own-address positive control: the peer netns (at
// peerIP) opens a flow to abox:boxPort from peerPort using its OWN address, then
// abox sends an ACK-only segment back on the reverse tuple and we report whether
// it arrived in the peer's namespace.
func aboxAnswersPeer(t *testing.T, peerNetns, peerIP string, boxPort, peerPort int, marker string) bool {
	t.Helper()
	forgeSYNToAbox(t, peerNetns, peerIP, peerPort, boxPort)
	return sniffInNetns(t, peerNetns, marker, func() {
		out, err := exec.Command("ip", "netns", "exec", spoofANetns, // #nosec G204 -- fixed argv, constant script
			"python3", "-c", forgeACKScript,
			spoofAAddr, peerIP, fmt.Sprint(boxPort), fmt.Sprint(peerPort), marker).CombinedOutput()
		if err != nil {
			t.Fatalf("abox ACK to %s: %v\n%s", peerIP, err, out)
		}
	})
}

// --- B5: an UNMARKED frame fails closed unless host-originated or from a
// known uplink -----------------------------------------------------------------
//
// A veth the daemon has not configured yet (a new instance before its first
// reconcile), or a namespace someone attached to the bridge by hand, has no
// sender hook, so its frames carry no mark. Before B5 those were trusted like
// the host's; now only ingress_ifindex 0 or an interface in trusted_iif is.
const (
	strayHostV = "ebpfload-sh"
	strayPeerV = "ebpfload-sp"
	strayNetns = "ebpfload-sns"
	strayAddr  = "10.251.0.4"
)

// TestAttachedProgram_UnmarkedNewInstanceCannotSeed: a bridge member with NO
// veth_policy entry forges a SYN from P into the enforced abox. Its frame is
// unmarked and its ingress interface is neither 0 nor a trusted uplink, so the
// seed is withheld and abox cannot reach P. Registering that interface as an
// uplink (what the daemon does for the default-route interfaces) then makes its
// unmarked frames trusted — proving the trusted_iif path and that the negative
// was the fail-closed rule, not a broken topology.
//
// Mutation guard: remove the unmarked-frame check and the stray's forgery seeds;
// this test fails.
func TestAttachedProgram_UnmarkedNewInstanceCannotSeed(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()
	if !loader.SupportsInboundReplies() {
		t.Fatal("loaded object has no inbound-flow/box_ip support — rebuild netpolicy.bpf.o for #2618")
	}
	br := setupSpoofBridge(t, loader, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); /* #nosec G204 -- fixed argv */ err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	// A third bridge member with NO veth_policy entry and no hooks attached.
	_ = exec.Command("ip", "link", "delete", strayHostV).Run()  // #nosec G204 -- fixed argv
	_ = exec.Command("ip", "netns", "delete", strayNetns).Run() // #nosec G204 -- fixed argv
	run("ip", "netns", "add", strayNetns)
	run("ip", "link", "add", strayHostV, "type", "veth", "peer", "name", strayPeerV)
	run("ip", "link", "set", strayHostV, "master", spoofBridge)
	run("ip", "link", "set", strayHostV, "up")
	run("ip", "link", "set", strayPeerV, "netns", strayNetns)
	run("ip", "netns", "exec", strayNetns, "ip", "addr", "add", strayAddr+spoofSubnet, "dev", strayPeerV)
	run("ip", "netns", "exec", strayNetns, "ip", "link", "set", strayPeerV, "up")
	run("ip", "netns", "exec", strayNetns, "ip", "route", "add", "default", "via", spoofBridgeIP)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", strayNetns).Run() // #nosec G204 -- fixed argv
		_ = exec.Command("ip", "link", "delete", strayHostV).Run()  // #nosec G204 -- fixed argv
	})
	strayIf, err := VethIndex(strayHostV)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", strayHostV, err)
	}

	if aboxExfil(t, br.raw, spoofBoxPort, spoofExfilPort, "unmarked-2618-baseline") {
		t.Fatal("precondition: abox reached P with no seed under enforce — enforcement is not active")
	}
	// The unconfigured member forges a SYN from P: unmarked, ingress = its veth
	// (not 0, not an uplink) — must NOT seed.
	forgeSYNToAbox(t, strayNetns, spoofExfilAddr, spoofExfilPort, spoofBoxPort)
	if aboxExfil(t, br.raw, spoofBoxPort, spoofExfilPort, "unmarked-2618-after-forged-seed") {
		t.Error("an UNMARKED frame from an unconfigured bridge member seeded the enforced box's egress — unmarked frames must fail closed unless host-originated or from a trusted uplink (#2618 B5)")
	}
	// Control: register the stray's interface as a trusted uplink and its
	// (still unmarked) frame now seeds — on distinct ports.
	if err := loader.SetTrustedIface(strayIf); err != nil {
		t.Fatalf("SetTrustedIface: %v", err)
	}
	t.Cleanup(func() { _ = loader.DeleteTrustedIface(strayIf) })
	forgeSYNToAbox(t, strayNetns, spoofExfilAddr, spoofCtrlExfilPort, spoofCtrlBoxPort)
	if !aboxExfil(t, br.raw, spoofCtrlBoxPort, spoofCtrlExfilPort, "unmarked-2618-trusted-uplink") {
		t.Fatal("positive control: a frame from a TRUSTED uplink interface did not seed — the trusted_iif path is broken, so the negative above proves nothing")
	}
	// And un-trusting it closes the door again (a third tuple).
	if err := loader.DeleteTrustedIface(strayIf); err != nil {
		t.Fatalf("DeleteTrustedIface: %v", err)
	}
	forgeSYNToAbox(t, strayNetns, spoofExfilAddr, spoofCtrlExfilPort+1, spoofCtrlBoxPort+1)
	if aboxExfil(t, br.raw, spoofCtrlBoxPort+1, spoofCtrlExfilPort+1, "unmarked-2618-untrusted-again") {
		t.Error("after DeleteTrustedIface the interface's unmarked frames still seed")
	}
}

// --- B4: the ROUTED path, with P in its own namespace -------------------------
//
// nbox is NOT on abox's bridge but on a point-to-point link, so the host
// L3-ROUTES its frames to abox: the sender hook's mark must survive forwarding.
// P lives in its own namespace behind a second p2p link — NOT as a host-local
// address, which would make the host drop a forged src=P frame as a martian
// before routing it (the reason the first version of this test could not fail).
// The host routes to P via that link and the test registers P's host-side veth
// as a trusted uplink, which is what P's frames are from the host's point of
// view. rp_filter is relaxed to loose on the host for the test (TC ingress, where
// the mark is set, runs before rp_filter, but strict mode would then drop the
// routed forgery) and restored afterwards.
const (
	routedNHostV = "ebpfload-rnh"
	routedNPeerV = "ebpfload-rnp"
	routedNNetns = "ebpfload-rnns"
	routedNHost  = "10.251.2.1" // host end of nbox's p2p link
	routedNAddr  = "10.251.2.2" // nbox
	routedPHostV = "ebpfload-rph"
	routedPPeerV = "ebpfload-rpp"
	routedPNetns = "ebpfload-rpns"
	routedPHost  = "10.251.3.1" // host end of P's p2p link
	routedPAddr  = "10.251.3.2" // P, the external address
	routedP2P    = "/30"
)

// sysctlSaveSet sets a sysctl for the test and restores the previous value.
func sysctlSaveSet(t *testing.T, key, value string) {
	t.Helper()
	prev, err := exec.Command("sysctl", "-n", key).Output() // #nosec G204 -- fixed argv
	if err != nil {
		t.Fatalf("sysctl -n %s: %v", key, err)
	}
	old := strings.TrimSpace(string(prev))
	if out, err := exec.Command("sysctl", "-wq", key+"="+value).CombinedOutput(); err != nil { // #nosec G204 -- fixed argv
		t.Fatalf("sysctl %s=%s: %v\n%s", key, value, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("sysctl", "-wq", key+"="+old).Run() }) // #nosec G204 -- fixed argv
}

// TestAttachedProgram_RoutedForgedSeedDoesNotOpenEgress forges from a neighbour
// whose frames the host routes (not bridges) to the enforced abox, with the
// target address P in its own namespace. A control first shows the routed
// neighbour's OWN-address seed opens (abox's answer arrives in nbox), then P's
// own flow seeds via the trusted uplink. The forgery from nbox "as P" must not
// open abox's egress to P.
//
// Mutation guard: remove the mark-based seed check and the routed forgery is
// trusted, the exfil reaches P's namespace, and this test fails.
func TestAttachedProgram_RoutedForgedSeedDoesNotOpenEgress(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()
	if !loader.SupportsInboundReplies() {
		t.Fatal("loaded object has no inbound-flow/box_ip support — rebuild netpolicy.bpf.o for #2618")
	}
	// abox on its bridge; the bridge's nbox and host-local P are unused here.
	setupSpoofBridge(t, loader, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); /* #nosec G204 -- fixed argv */ err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	for _, l := range []string{routedNHostV, routedPHostV} {
		_ = exec.Command("ip", "link", "delete", l).Run() // #nosec G204 -- fixed argv
	}
	for _, n := range []string{routedNNetns, routedPNetns} {
		_ = exec.Command("ip", "netns", "delete", n).Run() // #nosec G204 -- fixed argv
	}
	t.Cleanup(func() {
		for _, n := range []string{routedNNetns, routedPNetns} {
			_ = exec.Command("ip", "netns", "delete", n).Run() // #nosec G204 -- fixed argv
		}
		for _, l := range []string{routedNHostV, routedPHostV} {
			_ = exec.Command("ip", "link", "delete", l).Run() // #nosec G204 -- fixed argv
		}
	})
	for _, l := range []struct{ hostV, peerV, netns, hostIP, peerIP string }{
		{routedNHostV, routedNPeerV, routedNNetns, routedNHost, routedNAddr},
		{routedPHostV, routedPPeerV, routedPNetns, routedPHost, routedPAddr},
	} {
		run("ip", "netns", "add", l.netns)
		run("ip", "link", "add", l.hostV, "type", "veth", "peer", "name", l.peerV)
		run("ip", "addr", "add", l.hostIP+routedP2P, "dev", l.hostV)
		run("ip", "link", "set", l.hostV, "up")
		run("ip", "link", "set", l.peerV, "netns", l.netns)
		run("ip", "netns", "exec", l.netns, "ip", "addr", "add", l.peerIP+routedP2P, "dev", l.peerV)
		run("ip", "netns", "exec", l.netns, "ip", "link", "set", l.peerV, "up")
		run("ip", "netns", "exec", l.netns, "ip", "link", "set", "lo", "up")
		run("ip", "netns", "exec", l.netns, "ip", "route", "add", "default", "via", l.hostIP)
	}
	// Loose rp_filter for the test only, restored after: strict mode would drop
	// nbox's forged src=P on input (P's route is via the other link) before the
	// host could route it to abox.
	sysctlSaveSet(t, "net.ipv4.conf.all.rp_filter", "2")
	sysctlSaveSet(t, "net.ipv4.conf."+routedNHostV+".rp_filter", "2")
	sysctlSaveSet(t, "net.ipv4.conf."+routedPHostV+".rp_filter", "2")

	// The routed neighbour: a managed log_only entry with its own address, so its
	// sender hook marks its frames.
	c, err := netpolicy.Compile(&pb.NetworkPolicy{Tenant: "routed-nbox", Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rnCfg := CompileConfig(spoofTenantN, c)
	copy(rnCfg.BoxIP[:], net.ParseIP(routedNAddr).To4())
	rnIf, err := VethIndex(routedNHostV)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", routedNHostV, err)
	}
	if err := loader.SetVethPolicy(rnIf, rnCfg); err != nil {
		t.Fatalf("SetVethPolicy(routed nbox): %v", err)
	}
	if err := loader.AttachVeth(rnIf); err != nil {
		t.Fatalf("AttachVeth(routed nbox): %v", err)
	}
	t.Cleanup(func() { _ = loader.DetachVeth(rnIf) })
	// P's link is an uplink from the host's point of view.
	rpIf, err := VethIndex(routedPHostV)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", routedPHostV, err)
	}
	if err := loader.SetTrustedIface(rpIf); err != nil {
		t.Fatalf("SetTrustedIface(P link): %v", err)
	}
	t.Cleanup(func() { _ = loader.DeleteTrustedIface(rpIf) })

	// exfilToP: abox sends an ACK-only segment to P on the given tuple; did it
	// arrive in P's namespace?
	exfilToP := func(boxPort, pPort int, marker string) bool {
		t.Helper()
		return sniffInNetns(t, routedPNetns, marker, func() {
			out, err := exec.Command("ip", "netns", "exec", spoofANetns, // #nosec G204 -- fixed argv, constant script
				"python3", "-c", forgeACKScript,
				spoofAAddr, routedPAddr, fmt.Sprint(boxPort), fmt.Sprint(pPort), marker).CombinedOutput()
			if err != nil {
				t.Fatalf("abox ACK to P: %v\n%s", err, out)
			}
		})
	}

	if exfilToP(spoofBoxPort, spoofExfilPort, "routed-2618-baseline") {
		t.Fatal("precondition: abox reached routed P with no seed under enforce — enforcement is not active")
	}
	// Control 1: the routed neighbour seeds from its OWN address and abox's
	// answer arrives in nbox — the mark survives host forwarding and VALIDATED
	// frames seed.
	if !aboxAnswersPeer(t, routedNNetns, routedNAddr, spoofCtrlBoxPort, spoofCtrlExfilPort, "routed-2618-nbox-own-address") {
		t.Fatal("positive control: the routed neighbour's own-address seed did not open abox's egress to it — the routed validated path is broken")
	}
	// Control 2: P itself (via the trusted uplink) seeds and abox answers P.
	forgeSYNToAbox(t, routedPNetns, routedPAddr, spoofCtrlExfilPort+1, spoofCtrlBoxPort+1)
	if !exfilToP(spoofCtrlBoxPort+1, spoofCtrlExfilPort+1, "routed-2618-P-own-seed") {
		t.Fatal("positive control: P's own seed over the trusted uplink did not open abox's egress to P")
	}
	// The forgery: nbox sends a SYN "from P", routed by the host to abox. SEEN
	// without VALIDATED travels with it, so the seed is withheld.
	forgeSYNToAbox(t, routedNNetns, routedPAddr, spoofExfilPort, spoofBoxPort)
	if exfilToP(spoofBoxPort, spoofExfilPort, "routed-2618-after-forged-seed") {
		t.Error("a routed neighbour's forged SYN opened the enforced box's egress to P — the mark did not survive host forwarding, or the seed check is not mark-based (#2618 B4)")
	}
}

// forgeACKOptionsScript sends an ACK-only segment with a non-empty IP options
// field (ihl=6: four NOP/EOL option bytes), from the box's own source. parse_l4
// must treat ihl!=5 as unparsable (#2618 S2), so this is never a reply even on
// a seeded tuple. argv: src dst sport dport payload.
const forgeACKOptionsScript = `
import socket, struct, sys
src, dst, sport, dport, payload = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5].encode()
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff
tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4, 0x10, 65535, 0, 0)
pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp + payload)) + tcp[18:]
opts = b"\x01\x01\x01\x00"  # NOP, NOP, NOP, End-of-options: one 32-bit word
ihl = 5 + len(opts) // 4
ip = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, 20 + len(opts) + len(tcp) + len(payload), 0, 0, 64, 6, 0,
                 socket.inet_aton(src), socket.inet_aton(dst)) + opts
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for _ in range(3):
    s.sendto(ip + tcp + payload, (dst, 0))
`

// TestAttachedProgram_IPOptionsSegmentIsNotAReply pins #2618 S2: a packet whose
// IP header carries options (ihl!=5) is never treated as a reply, so a box
// cannot ride a validly-seeded tuple out with an options-bearing segment. A
// plain ACK on the same tuple does reach P (the positive control), isolating the
// options behaviour.
func TestAttachedProgram_IPOptionsSegmentIsNotAReply(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()
	if !loader.SupportsInboundReplies() {
		t.Fatal("loaded object has no inbound-flow/box_ip support — rebuild netpolicy.bpf.o for #2618")
	}
	br := setupSpoofBridge(t, loader, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)

	// Validly seed a flow from the host (P) to abox:spoofCtrlBoxPort.
	forgeSYNToAbox(t, "", spoofExfilAddr, spoofCtrlExfilPort, spoofCtrlBoxPort)
	// A plain ACK on the seeded tuple reaches P: the seed is live.
	if !aboxExfil(t, br.raw, spoofCtrlBoxPort, spoofCtrlExfilPort, "s2-plain-ack") {
		t.Fatal("positive control: a plain ACK on a validly seeded tuple did not reach P")
	}

	// The SAME tuple, but with IP options: parse_l4 bails, so it is not a reply
	// and is judged as egress under enforce: it must not reach P.
	marker := "s2-options-segment"
	out, err := exec.Command("ip", "netns", "exec", spoofANetns, // #nosec G204 -- fixed argv, constant script
		"python3", "-c", forgeACKOptionsScript,
		spoofAAddr, spoofExfilAddr, fmt.Sprint(spoofCtrlBoxPort), fmt.Sprint(spoofCtrlExfilPort), marker).CombinedOutput()
	if err != nil {
		t.Fatalf("send options segment from abox: %v\n%s", err, out)
	}
	buf := make([]byte, 2048)
	_ = br.raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := br.raw.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break // good: the options segment never arrived
		}
		if err != nil {
			t.Fatalf("raw read: %v", err)
		}
		if bytes.Contains(buf[:n], []byte(marker)) {
			t.Error("an IP-options segment rode a seeded tuple out to P: parse_l4 did not fail closed on ihl!=5 (#2618 S2)")
			break
		}
	}
}
