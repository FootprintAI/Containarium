//go:build ebpf_load

package netbpf

import (
	"fmt"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3166: the virtual-patch deny (#660) and per-flow accounting (#627) share
// parse_l4's guard — a packet whose IP header carries options (ihl != 5) or that
// is a fragment has no trustworthy L4 ports. These tests pin, on a real kernel:
//
//   - TestAttachedProgram_PortScopedDenyNotEvadedByIPOptions: a port-scoped deny
//     cannot be evaded with IP options or fragmentation — an unknown port on a
//     port-carrying protocol fails closed (the rule's address and proto decide).
//   - TestAttachedProgram_PortScopedUDPDenyNotEvadedByIPOptions: the same for
//     a UDP rule.
//   - TestAttachedProgram_FragmentsAreNotAccounted: fragments are skipped by the
//     flow accounting on the sender hook (not tallied under port 0); an
//     options-bearing non-fragment is tallied under ports 0, like any packet
//     whose ports are unknown.
//   - TestAttachedProgram_ReplyFragmentsAreNotAccounted: the same for reply
//     accounting on the veth egress hook.

const (
	l4GuardDenyPort  = 8690 // the deny rule's port
	l4GuardOtherPort = 8691 // same host, not denied
	l4GuardSport     = 40690
	l4GuardUDPSport  = 4242
	l4GuardUDPDport  = 4343
)

// sendCraftedScript sends three IPv4 packets with a hand-built header from a raw
// socket, so the test controls ihl and frag_off. argv: src dst proto(tcp|udp)
// sport dport options(0|1) frag(none|mf|offset) payload. options=1 adds one
// 32-bit word of NOP/EOL options (ihl=6); frag=mf sets More-Fragments at offset
// 0 (a first fragment, L4 header present); frag=offset sets a non-zero fragment
// offset (a later fragment); frag=trunc sends an unfragmented packet whose L4
// header is cut after 4 bytes (a truncated header). An optional 9th argument
// names an interface to inject the frame onto directly (AF_PACKET).
const sendCraftedScript = `
import socket, struct, sys
src, dst, proto, sport, dport, opt, frag, payload = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6] == "1", sys.argv[7], sys.argv[8].encode()
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff
if proto == "tcp":
    pnum = 6
    l4 = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)  # SYN
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, pnum, len(l4) + len(payload))
    l4 = l4[:16] + struct.pack("!H", csum(pseudo + l4 + payload)) + l4[18:]
else:
    pnum = 17
    l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
opts = b"\x01\x01\x01\x00" if opt else b""
ihl = 5 + len(opts) // 4
if frag == "trunc":
    # An unfragmented packet cut inside its L4 header: the ports are not in the
    # linear data, so parse_l4 reports them unknown.
    l4 = l4[:4]
    payload = b""
    frag = "none"
frag_off = {"none": 0, "mf": 0x2000, "offset": 1}[frag]
ip = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, 20 + len(opts) + len(l4) + len(payload), 0x3166, frag_off, 64, pnum, 0,
                 socket.inet_aton(src), socket.inet_aton(dst)) + opts
iface = sys.argv[9] if len(sys.argv) > 9 else ""
if iface:
    # Inject the frame straight onto the veth with an AF_PACKET socket, below
    # netfilter: a locally-sent fragment would otherwise be swallowed by
    # conntrack's defragmentation before it reaches the TC egress hook.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    eth = b"\x02\x00\x00\x00\x31\x66" + b"\x02\x00\x00\x00\x31\x67" + b"\x08\x00"
    for _ in range(3):
        s.send(eth + ip + l4 + payload)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    for _ in range(3):
        s.sendto(ip + l4 + payload, (dst, 0))
`

// craftedPacket describes one sendCraftedScript invocation from the box netns
// to the host-side address.
type craftedPacket struct {
	proto   string // "tcp" | "udp" (the script's argv vocabulary)
	sport   int
	dport   int
	options bool
	frag    string // "none" | "mf" | "offset" | "trunc"
}

func sendCrafted(t *testing.T, p craftedPacket) {
	t.Helper()
	runCrafted(t, p, ebpfLoadPeerAddr, ebpfLoadHostAddr, "", "ip", "netns", "exec", ebpfLoadNetns)
}

// sendCraftedToBox sends p from the host namespace to the box, so it crosses the
// host veth's TC egress hook (the reply direction).
func sendCraftedToBox(t *testing.T, p craftedPacket) {
	t.Helper()
	runCrafted(t, p, ebpfLoadHostAddr, ebpfLoadPeerAddr, ebpfLoadHostVeth)
}

func runCrafted(t *testing.T, p craftedPacket, src, dst, iface string, prefix ...string) {
	t.Helper()
	opt := "0"
	if p.options {
		opt = "1"
	}
	argv := append(append([]string{}, prefix...), "python3", "-c", sendCraftedScript,
		src, dst, p.proto, fmt.Sprint(p.sport), fmt.Sprint(p.dport), opt, p.frag, "l4-guard-3166", iface)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- fixed argv, constant script
	if err != nil {
		t.Fatalf("send crafted %+v %s -> %s: %v\n%s", p, src, dst, err, out)
	}
}

// attachL4GuardBox loads the object and attaches it to the shared veth with a
// log-only policy that allows the host address, so only an explicit deny rule
// can move the would-deny counter.
func attachL4GuardBox(t *testing.T, denyRules []*pb.NetworkPolicyDenyRule) (*Loader, int) {
	t.Helper()
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = loader.Close() })
	c, err := netpolicy.Compile(&pb.NetworkPolicy{
		Tenant:      "l4-guard-box",
		EgressCidrs: []string{ebpfLoadHostAddr + "/32"},
		DenyRules:   denyRules,
		Mode:        pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}
	if err := loader.SetVethPolicy(ifindex, CompileConfig(ebpfLoadTenant, c)); err != nil {
		t.Fatalf("SetVethPolicy: %v", err)
	}
	egress, err := CompileEgress(ebpfLoadTenant, c)
	if err != nil {
		t.Fatalf("CompileEgress: %v", err)
	}
	for _, e := range egress {
		if err := loader.AddEgress(e); err != nil {
			t.Fatalf("AddEgress: %v", err)
		}
	}
	deny, err := CompileDeny(ebpfLoadTenant, c)
	if err != nil {
		t.Fatalf("CompileDeny: %v", err)
	}
	for _, d := range deny {
		if err := loader.AddDeny(d); err != nil {
			t.Fatalf("AddDeny: %v", err)
		}
	}
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}
	t.Cleanup(func() { _ = loader.DetachVeth(ifindex) })
	return loader, ifindex
}

// seenAfterSend sends p and returns the (seen, would_deny) deltas, waiting until
// the program has evaluated all three packets so a zero would-deny delta means
// "evaluated and not denied", not "not evaluated yet".
func seenAfterSend(t *testing.T, loader *Loader, p craftedPacket) (seen, wouldDeny uint64) {
	t.Helper()
	seen0, deny0, err := loader.Stats()
	if err != nil {
		t.Fatalf("Stats (before): %v", err)
	}
	sendCrafted(t, p)
	var seen1, deny1 uint64
	deadline := time.Now().Add(3 * time.Second)
	for {
		seen1, deny1, err = loader.Stats()
		if err != nil {
			t.Fatalf("Stats (after): %v", err)
		}
		if seen1-seen0 >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return seen1 - seen0, deny1 - deny0
}

func TestAttachedProgram_PortScopedDenyNotEvadedByIPOptions(t *testing.T) {
	loader, _ := attachL4GuardBox(t, []*pb.NetworkPolicyDenyRule{
		{Cidr: ebpfLoadHostAddr + "/32", Port: l4GuardDenyPort, Proto: "tcp"},
	})
	if !loader.HasDenyRules() {
		t.Fatal("object has no deny_cidr map — rebuild netpolicy.bpf.o")
	}

	runDenyCases(t, loader, []denyCase{
		// Controls: the rule is port-scoped and the address is allowed, so only
		// the denied port moves the counter.
		{"plain SYN to the denied port", craftedPacket{"tcp", l4GuardSport, l4GuardDenyPort, false, "none"}, true},
		{"plain SYN to another port", craftedPacket{"tcp", l4GuardSport, l4GuardOtherPort, false, "none"}, false},
		// The evasions: the port cannot be read, so the port match fails closed.
		{"IP-options SYN to the denied port", craftedPacket{"tcp", l4GuardSport, l4GuardDenyPort, true, "none"}, true},
		{"first fragment to the denied port", craftedPacket{"tcp", l4GuardSport, l4GuardDenyPort, false, "mf"}, true},
		{"later fragment (no L4 header)", craftedPacket{"tcp", l4GuardSport, l4GuardDenyPort, false, "offset"}, true},
		// Truncated L4 header: the ports are not in the linear data, so the
		// port is unknown even for a packet to another port. Deliberate
		// fail-closed behaviour change (#3166).
		{"truncated TCP header to the denied port", craftedPacket{"tcp", l4GuardSport, l4GuardDenyPort, false, "trunc"}, true},
		{"truncated TCP header to another port", craftedPacket{"tcp", l4GuardSport, l4GuardOtherPort, false, "trunc"}, true},
		// Over-blocking by design: a fragment whose real port differs is denied.
		{"first fragment to another port", craftedPacket{"tcp", l4GuardSport, l4GuardOtherPort, false, "mf"}, true},
		// The proto scope still decides: the IP header's protocol is always read.
		{"IP-options UDP to the denied port", craftedPacket{"udp", l4GuardSport, l4GuardDenyPort, true, "none"}, false},
		{"UDP fragment under a tcp rule", craftedPacket{"udp", l4GuardSport, l4GuardDenyPort, false, "mf"}, false},
	})
}

// A UDP port-scoped rule is evaded the same way and closed the same way.
func TestAttachedProgram_PortScopedUDPDenyNotEvadedByIPOptions(t *testing.T) {
	loader, _ := attachL4GuardBox(t, []*pb.NetworkPolicyDenyRule{
		{Cidr: ebpfLoadHostAddr + "/32", Port: l4GuardDenyPort, Proto: "udp"},
	})
	if !loader.HasDenyRules() {
		t.Fatal("object has no deny_cidr map — rebuild netpolicy.bpf.o")
	}
	runDenyCases(t, loader, []denyCase{
		{"plain UDP to the denied port", craftedPacket{"udp", l4GuardSport, l4GuardDenyPort, false, "none"}, true},
		{"plain UDP to another port", craftedPacket{"udp", l4GuardSport, l4GuardOtherPort, false, "none"}, false},
		{"IP-options UDP to the denied port", craftedPacket{"udp", l4GuardSport, l4GuardDenyPort, true, "none"}, true},
		{"UDP first fragment", craftedPacket{"udp", l4GuardSport, l4GuardDenyPort, false, "mf"}, true},
		{"UDP later fragment", craftedPacket{"udp", l4GuardSport, l4GuardDenyPort, false, "offset"}, true},
		{"truncated UDP header to another port", craftedPacket{"udp", l4GuardSport, l4GuardOtherPort, false, "trunc"}, true},
		{"TCP fragment under a udp rule", craftedPacket{"tcp", l4GuardSport, l4GuardDenyPort, false, "mf"}, false},
	})
}

type denyCase struct {
	name     string
	pkt      craftedPacket
	wantDeny bool
}

func runDenyCases(t *testing.T, loader *Loader, cases []denyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen, denied := seenAfterSend(t, loader, tc.pkt)
			if seen < 3 {
				t.Fatalf("the program evaluated %d of 3 packets — the crafted packets did not reach the attached hook", seen)
			}
			if tc.wantDeny && denied == 0 {
				t.Errorf("%+v: would_deny did not move — a port-scoped deny was evaded (#3166)", tc.pkt)
			}
			if !tc.wantDeny && denied != 0 {
				t.Errorf("%+v: would_deny moved by %d — the deny rule fired outside its scope", tc.pkt, denied)
			}
		})
	}
}

func TestAttachedProgram_FragmentsAreNotAccounted(t *testing.T) {
	loader, ifindex := attachL4GuardBox(t, nil)
	if !loader.HasFlowAccounting() {
		t.Fatal("object has no flows map — rebuild netpolicy.bpf.o")
	}
	peer := netip.MustParseAddr(ebpfLoadPeerAddr)
	host := netip.MustParseAddr(ebpfLoadHostAddr)

	// udpFlows returns this test's UDP flow entries (box -> host on this veth).
	udpFlows := func() []FlowRecord {
		t.Helper()
		recs, err := loader.Flows()
		if err != nil {
			t.Fatalf("Flows: %v", err)
		}
		var out []FlowRecord
		for _, r := range recs {
			if int(r.Ifindex) == ifindex && r.Src() == peer && r.Dst() == host && r.Proto == 17 {
				out = append(out, r)
			}
		}
		return out
	}
	send := func(p craftedPacket) {
		t.Helper()
		if seen, _ := seenAfterSend(t, loader, p); seen < 3 {
			t.Fatalf("%+v: the program evaluated %d of 3 packets — the crafted packets did not reach the attached hook", p, seen)
		}
	}

	// Fragments, first and later: skipped by the accounting entirely.
	send(craftedPacket{"udp", l4GuardUDPSport, l4GuardUDPDport, false, "mf"})
	send(craftedPacket{"udp", l4GuardUDPSport, l4GuardUDPDport, false, "offset"})
	if got := udpFlows(); len(got) != 0 {
		t.Fatalf("fragments were accounted: %+v — want no flow entry for a fragment (#3166: accounting skips fragments)", got)
	}

	// Control: a plain datagram is accounted under its real ports.
	send(craftedPacket{"udp", l4GuardUDPSport, l4GuardUDPDport, false, "none"})
	got := udpFlows()
	if len(got) != 1 || got[0].Sport != l4GuardUDPSport || got[0].Dport != l4GuardUDPDport || got[0].Packets != 3 {
		t.Fatalf("plain datagrams: got %+v, want one entry %d->%d with 3 packets", got, l4GuardUDPSport, l4GuardUDPDport)
	}

	// An options-bearing non-fragment: accounted, but under ports 0 — its port
	// bytes are not read, as for any packet whose ports are unknown.
	send(craftedPacket{"udp", l4GuardUDPSport, l4GuardUDPDport, true, "none"})
	var zero *FlowRecord
	for _, r := range udpFlows() {
		if r.Sport == 0 && r.Dport == 0 {
			zero = &r
		}
	}
	if zero == nil || zero.Packets != 3 {
		t.Fatalf("IP-options datagrams: got %+v, want one ports-0 entry with 3 packets", zero)
	}
}

// The egress hook's account_reply is gated on !ip_is_fragment too (#3166): a
// reply-direction fragment (host -> box) has no readable ports and must not
// create a ports-0 flow entry. Without the gate, account_reply tallies it under
// the swapped key (box, host, 0, 0).
func TestAttachedProgram_ReplyFragmentsAreNotAccounted(t *testing.T) {
	loader, ifindex := attachL4GuardBox(t, nil)
	if !loader.HasFlowAccounting() {
		t.Fatal("object has no flows map — rebuild netpolicy.bpf.o")
	}
	// attachL4GuardBox attaches only the sender (ingress) hook; the reply
	// accounting under test lives on the TC egress hook.
	if err := loader.AttachVethEgress(ifindex); err != nil {
		t.Fatalf("AttachVethEgress: %v", err)
	}
	peer := netip.MustParseAddr(ebpfLoadPeerAddr)
	host := netip.MustParseAddr(ebpfLoadHostAddr)
	// Reply entries for host -> box UDP are keyed in request orientation:
	// src = box (peer), dst = host.
	replyFlows := func() []FlowRecord {
		t.Helper()
		recs, err := loader.Flows()
		if err != nil {
			t.Fatalf("Flows: %v", err)
		}
		var out []FlowRecord
		for _, r := range recs {
			if int(r.Ifindex) == ifindex && r.Src() == peer && r.Dst() == host && r.Proto == 17 {
				out = append(out, r)
			}
		}
		return out
	}

	// Control first: a plain reply datagram is accounted under its real ports,
	// proving the egress hook is attached and running before any fragment is
	// sent, so the fragment check below cannot pass because the hook was dead.
	sendCraftedToBox(t, craftedPacket{"udp", l4GuardUDPDport, l4GuardUDPSport, false, "none"})
	checkPlain := func(when string) {
		t.Helper()
		got := replyFlows()
		if len(got) != 1 || got[0].Sport != l4GuardUDPSport || got[0].Dport != l4GuardUDPDport || got[0].RxPackets != 3 {
			t.Fatalf("%s: got %+v, want one entry %d->%d with 3 rx packets (#3166: account_reply skips fragments)", when, got, l4GuardUDPSport, l4GuardUDPDport)
		}
	}
	checkPlain("plain reply datagrams")

	// Then the fragments: the entry must be unchanged — no second entry and no
	// extra rx packets. The send returns once the frame has been through the
	// egress hook (an AF_PACKET send), so there is nothing to wait for.
	sendCraftedToBox(t, craftedPacket{"udp", l4GuardUDPDport, l4GuardUDPSport, false, "mf"})
	sendCraftedToBox(t, craftedPacket{"udp", l4GuardUDPDport, l4GuardUDPSport, false, "offset"})
	checkPlain("after reply fragments")
}
