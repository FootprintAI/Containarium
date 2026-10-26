//go:build ebpf_load

package netbpf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
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

// Addresses for the spoofed-seed topology, all distinct from the single-pair
// fixture TestMain builds (10.250.111.x) and from the other load tests.
const (
	spoofBridge   = "ebpfload-br"
	spoofAHostV   = "ebpfload-ah" // abox host veth (on the bridge)
	spoofAPeerV   = "ebpfload-ap"
	spoofANetns   = "ebpfload-ans"
	spoofNHostV   = "ebpfload-nh" // neighbour box host veth (on the bridge)
	spoofNPeerV   = "ebpfload-np"
	spoofNNetns   = "ebpfload-nns"
	spoofBridgeIP = "10.251.0.1"
	spoofAAddr    = "10.251.0.2"
	spoofNAddr    = "10.251.0.3"
	spoofSubnet   = "/24"
	spoofTenantA  = uint32(11)
	spoofTenantN  = uint32(12)
	// P is an external address reached via the bridge host, with a listener on
	// spoofExfilPort. The neighbour forges a SYN "from" P:spoofExfilPort so the
	// seed's ports line up with abox's dial below.
	spoofExfilAddr = "10.251.9.9"
	spoofExfilPort = 9999
	spoofBoxPort   = 7777 // abox's fixed source port, = the forged SYN's dport
)

// forgeSYNScript sends N TCP SYN segments (no ACK) with a FORGED source
// address, building the whole IP header so the kernel does not overwrite the
// source with the netns's own address (IP_HDRINCL). The box is root in its own
// netns, so it can spoof any source — which is exactly what source validation
// has to stop. argv: src dst sport dport count.
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
# TCP header: data offset 5<<4 in byte 12, flags 0x02 = SYN only.
tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)
pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
c = csum(pseudo + tcp)
tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
# IP header with the forged source; kernel fills id and checksum (0) under HDRINCL.
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                 socket.inet_aton(src), socket.inet_aton(dst))
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for _ in range(count):
    s.sendto(ip + tcp, (dst, 0))
`

// TestAttachedProgram_SpoofedInboundSeedDoesNotOpenEgress is the source-validation
// guard (#2618 decision, option (a)) on a real kernel. Topology: a bridge with
// two managed veths, abox (enforce, empty allow-list) and a neighbour box nbox
// (log_only — the worst case, since nbox's own hook only logs its forgery). nbox
// forges a TCP SYN whose source is an external address P, destined to abox, so
// that — if the program seeded the inbound-flow map from that forgery — the
// reverse tuple P:9999 <-> abox:7777 would look like an open flow. abox then
// exfiltrates by sending ACK-only segments to P:9999 from source port 7777
// (the exact reverse of the forged seed): an ACK is not a fresh SYN, so it is
// exactly the segment inbound_reply would wave through on a seeded flow — and
// it is the channel #3070's forged-ACK finding identified. Source validation at
// abox's receiving veth rejects the seed (the frame entered on nbox's veth but
// carries P, not nbox's own address), so the ACK is judged as egress and
// dropped under enforce, never reaching P.
//
// Remove the source-validation check in track_inbound and the forged ACK
// reaches P, i.e. this test fails — which is the point: it is the mutation guard
// the decision asks for.
func TestAttachedProgram_SpoofedInboundSeedDoesNotOpenEgress(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()
	if !loader.SupportsInboundReplies() {
		t.Fatal("loaded object has no inbound-flow/box_ip support — rebuild netpolicy.bpf.o for #2618")
	}

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); /* #nosec G204 -- fixed argv */ err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	// A second bridge topology, separate from TestMain's single veth pair.
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

	// P: an external address on the bridge host, routed from both boxes via the
	// bridge. A raw IP socket on it sees every TCP segment delivered, including
	// ACK-only ones no TCP stack would answer — the exfil channel's receiver.
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
	// abox: enforce, empty allow-list, its own address known (so source
	// validation and inbound tracking are active).
	setBoxPolicy := func(ifindex int, tenant uint32, addr string, mode pb.NetworkPolicyMode) {
		t.Helper()
		c, err := netpolicy.Compile(&pb.NetworkPolicy{Tenant: fmt.Sprintf("spoof-%d", tenant), Mode: mode})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		cfg := CompileConfig(tenant, c)
		ip4 := net.ParseIP(addr).To4()
		if ip4 == nil {
			t.Fatalf("not an IPv4 address: %q", addr)
		}
		copy(cfg.BoxIP[:], ip4)
		if err := loader.SetVethPolicy(ifindex, cfg); err != nil {
			t.Fatalf("SetVethPolicy: %v", err)
		}
	}
	setBoxPolicy(aIf, spoofTenantA, spoofAAddr, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE)
	// nbox: log_only. Its own hook only LOGS the forgery it sends, so nothing but
	// abox's receiving-side source validation can stop the seed.
	setBoxPolicy(nIf, spoofTenantN, spoofNAddr, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY)
	for _, idx := range []int{aIf, nIf} {
		if err := loader.AttachVeth(idx); err != nil {
			t.Fatalf("AttachVeth(%d): %v", idx, err)
		}
		if err := loader.AttachVethEgress(idx); err != nil {
			t.Fatalf("AttachVethEgress(%d): %v", idx, err)
		}
		t.Cleanup(func() { _ = loader.DetachVeth(idx) })
	}

	// aboxExfilsToP sends ACK-only segments abox -> P from source port 7777 to
	// 9999 (the reverse of the forged seed), tagged with marker, and reports
	// whether any reached P's raw socket.
	aboxExfilsToP := func(marker string) bool {
		t.Helper()
		out, err := exec.Command("ip", "netns", "exec", spoofANetns, // #nosec G204 -- fixed argv, constant script
			"python3", "-c", forgeACKScript,
			spoofAAddr, spoofExfilAddr, fmt.Sprint(spoofBoxPort), fmt.Sprint(spoofExfilPort), marker).CombinedOutput()
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

	// Precondition: with no seed at all, abox's ACK to P is judged as egress and
	// dropped (empty allow-list, enforce). If it already reached P, the rest
	// would prove nothing.
	if aboxExfilsToP("spoof-2618-baseline") {
		t.Fatal("precondition: abox reached P with an empty allow-list under enforce and no seed — enforcement is not active")
	}

	// nbox forges SYNs from P to abox:spoofBoxPort (sport = spoofExfilPort), so a
	// seed, if planted, would match abox's exfil 5-tuple exactly.
	out, err := exec.Command("ip", "netns", "exec", spoofNNetns, // #nosec G204 -- fixed argv, constant script
		"python3", "-c", forgeSYNScript,
		spoofExfilAddr, spoofAAddr, fmt.Sprint(spoofExfilPort), fmt.Sprint(spoofBoxPort), "5").CombinedOutput()
	if err != nil {
		t.Fatalf("forge SYN from nbox: %v\n%s", err, out)
	}
	time.Sleep(300 * time.Millisecond) // let the forged frames traverse the bridge and hit abox's egress hook

	// The seed must have been rejected: abox's ACK still cannot reach P. Removing
	// the source-validation check in track_inbound makes the ACK arrive and this
	// test fail.
	if aboxExfilsToP("spoof-2618-after-forged-seed") {
		t.Error("a neighbour's forged SYN from an external address opened the enforced box's egress to it — source validation (#2618) is not holding")
	}
}
