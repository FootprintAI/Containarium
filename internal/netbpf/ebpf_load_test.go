//go:build ebpf_load

// Real-kernel coverage for the netpolicy eBPF object (#1663). Every other
// test in this package runs against a mocked/stubbed BPF layer or doesn't
// touch the kernel at all — this is the one place that proves the compiled
// object (built by `make build-bpf`) actually passes the kernel verifier,
// actually attaches its TC hooks via AttachTCX, and its attached program
// actually evaluates real packets, not just that Load/AttachVeth returned no
// error. Gated behind -tags=ebpf_load (mirrors this repo's -tags=incus /
// -tags=integration convention) because it needs CAP_BPF/CAP_NET_ADMIN, a
// compiled netpolicy.bpf.o, and a kernel that supports AttachTCX (≥6.6) —
// none of which a normal dev laptop `go test ./...` has.
//
// Run via .github/workflows/ebpf-load.yml, which builds the object and
// creates the veth pair + netns this file expects before invoking:
//
//	sudo -E env "PATH=$PATH" go test -tags=ebpf_load -v ./internal/netbpf/...
//
// TestMain creates the veth pair and netns itself (see setupEbpfLoadEnv)
// rather than relying solely on a workflow shell step, so the whole
// environment this file needs is defined in one place, in Go, next to the
// tests that consume it — easier to read and debug from a CI log than a
// shell/Go handoff for interface names and namespaces would be.
package netbpf

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Test topology: a throwaway veth pair, one end (ebpfLoadHostVeth) left in
// the host's default network namespace — this is the side the loader
// attaches to, playing the role of a container's HOST veth in production.
// The other end (ebpfLoadPeerVeth) is moved into its own netns
// (ebpfLoadNetns) and given a peer IP — playing the role of the container
// itself. Traffic generated from inside the netns arrives as TC_INGRESS on
// the host-side veth, which is exactly the direction AttachVeth's doc
// comment describes ("TC_INGRESS ... the sender side of every flow").
const (
	ebpfLoadHostVeth = "ebpfload-h"
	ebpfLoadPeerVeth = "ebpfload-p"
	ebpfLoadNetns    = "ebpfload-ns"
	ebpfLoadHostAddr = "10.250.111.1"
	ebpfLoadPeerAddr = "10.250.111.2"
	ebpfLoadPrefix   = "/30"
	ebpfLoadTenant   = uint32(1)
	ebpfLoadObjPath  = "netpolicy.bpf.o" // matches BPF_OBJ's basename; Makefile writes it under internal/netbpf, i.e. this package's own directory
)

// TestMain creates the shared kernel-level fixtures once for every
// -tags=ebpf_load test in this package, and tears them down afterward. A
// setup failure here (no CAP_NET_ADMIN, `ip` missing, etc.) fails the whole
// run loudly rather than letting individual tests report confusing,
// unrelated errors.
func TestMain(m *testing.M) {
	if err := setupEbpfLoadEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "ebpf_load: setup failed: %v\n", err)
		// Best-effort cleanup in case setup got partway through before
		// failing (e.g. netns created, veth add failed).
		teardownEbpfLoadEnv()
		os.Exit(1)
	}
	code := m.Run()
	teardownEbpfLoadEnv()
	os.Exit(code)
}

func setupEbpfLoadEnv() error {
	if _, err := os.Stat(ebpfLoadObjPath); err != nil {
		return fmt.Errorf("%s not found — run `make build-bpf` before this test (that's the workflow's job): %w", ebpfLoadObjPath, err)
	}

	steps := [][]string{
		{"ip", "netns", "add", ebpfLoadNetns},
		{"ip", "link", "add", ebpfLoadHostVeth, "type", "veth", "peer", "name", ebpfLoadPeerVeth},
		{"ip", "link", "set", ebpfLoadPeerVeth, "netns", ebpfLoadNetns},
		{"ip", "addr", "add", ebpfLoadHostAddr + ebpfLoadPrefix, "dev", ebpfLoadHostVeth},
		{"ip", "link", "set", ebpfLoadHostVeth, "up"},
		{"ip", "link", "set", "lo", "up"}, // host lo; usually already up, asserted rather than assumed
		{"ip", "netns", "exec", ebpfLoadNetns, "ip", "addr", "add", ebpfLoadPeerAddr + ebpfLoadPrefix, "dev", ebpfLoadPeerVeth},
		{"ip", "netns", "exec", ebpfLoadNetns, "ip", "link", "set", ebpfLoadPeerVeth, "up"},
		{"ip", "netns", "exec", ebpfLoadNetns, "ip", "link", "set", "lo", "up"},
	}
	for _, args := range steps {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); /* #nosec G204 -- fixed argv, no user input */ err != nil {
			return fmt.Errorf("%v: %w\n%s", args, err, out)
		}
	}
	return nil
}

func teardownEbpfLoadEnv() {
	// Deleting the host-side end of a veth pair removes both ends; deleting
	// the netns cleans up anything still inside it. Both best-effort — a
	// leaked interface/netns on a GitHub-hosted ephemeral runner doesn't
	// matter (the VM is destroyed at job end), this is hygiene for anyone
	// re-running the package interactively on a real machine.
	_ = exec.Command("ip", "link", "delete", ebpfLoadHostVeth).Run() // #nosec G204 -- fixed argv
	_ = exec.Command("ip", "netns", "delete", ebpfLoadNetns).Run()   // #nosec G204 -- fixed argv
}

// TestLoad_RealObjectPassesVerifier proves the object make build-bpf just
// compiled is accepted by the real kernel verifier — the failure mode a
// verifier-rejected instruction or a map/program mismatch takes today
// (silently, since go build/go test never load the real object) closes
// here instead.
func TestLoad_RealObjectPassesVerifier(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load(%q): %v", ebpfLoadObjPath, err)
	}
	defer func() { _ = loader.Close() }()

	if !loader.hasEgressProgram() {
		t.Log("object has no egress program (pre-#631 build) — ingress-only coverage, not a failure")
	}
}

// TestAttachVeth_RealInterface proves AttachTCX actually succeeds on this
// runner's kernel — the design doc's flagged, unverified-until-now
// assumption that AttachTCX's documented "kernel >= 6.6" requirement holds
// on ubuntu-latest.
func TestAttachVeth_RealInterface(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()

	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}

	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth(%d): %v", ifindex, err)
	}
	// Idempotent per the doc comment — attaching twice must not error or
	// create a second link.
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("second AttachVeth(%d) (idempotency): %v", ifindex, err)
	}

	if err := loader.AttachVethEgress(ifindex); err != nil {
		t.Fatalf("AttachVethEgress(%d): %v", ifindex, err)
	}
}

// TestAttachedProgram_EvaluatesRealTraffic is the actual point of this
// lane: not that AttachTCX returned nil, but that the attached program
// evaluates real packets. Installs a policy (tenant + a deny rule for the
// peer's address), sends real ICMP traffic from the peer netns across the
// veth pair, and asserts the seen/would-deny counters — "the validator's
// success signal" per Loader.Stats's doc comment, the same signal
// cmd/ebpf-phaseA's manual validator watches — actually moved.
func TestAttachedProgram_EvaluatesRealTraffic(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()

	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}

	if err := loader.SetVethPolicy(ifindex, PolicyConfig{TenantID: ebpfLoadTenant, Mode: ModeLogOnly}); err != nil {
		t.Fatalf("SetVethPolicy: %v", err)
	}

	if loader.HasDenyRules() {
		peer, err := netip.ParseAddr(ebpfLoadPeerAddr)
		if err != nil {
			t.Fatalf("parse peer addr: %v", err)
		}
		if err := loader.AddDeny(DenyEntry{
			PrefixLen: 32 + 32, // exact tenant match + a /32 host route, mirroring EgressEntry's PrefixLen convention
			TenantID:  ebpfLoadTenant,
			Addr:      peer.As4(),
		}); err != nil {
			t.Fatalf("AddDeny: %v", err)
		}
	} else {
		t.Log("object has no deny_cidr map (pre-#660 build) — asserting seen only, not would_deny")
	}

	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}

	seenBefore, denyBefore, err := loader.Stats()
	if err != nil {
		t.Fatalf("Stats (before): %v", err)
	}

	// Real traffic: ping from the peer netns to the host-side address. That
	// direction (peer -> host) is what arrives as TC_INGRESS on the
	// host-side veth, which is what's attached above.
	out, err := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv
		"ping", "-c", "3", "-i", "0.2", "-W", "1", ebpfLoadHostAddr).CombinedOutput()
	if err != nil {
		// ping itself may report loss (irrelevant — a log-only/deny policy
		// doesn't actually drop, and ICMP isn't guaranteed anyway); what
		// matters below is whether the KERNEL PROGRAM saw the packets, so a
		// nonzero ping exit code alone isn't fatal. Still log the output for
		// a failing run's diagnostics.
		t.Logf("ping exit: %v\n%s", err, out)
	}

	// Give the map update a moment to be observable (no synchronization
	// primitive between "packet processed" and "counter read" other than
	// the ping call itself having returned, and TC processing is
	// effectively synchronous with packet delivery, but poll briefly rather
	// than assume zero latency).
	var seenAfter, denyAfter uint64
	deadline := time.Now().Add(3 * time.Second)
	for {
		seenAfter, denyAfter, err = loader.Stats()
		if err != nil {
			t.Fatalf("Stats (after): %v", err)
		}
		if seenAfter > seenBefore {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if seenAfter <= seenBefore {
		t.Fatalf("seen counter did not increase after sending real traffic across the attached veth: before=%d after=%d — "+
			"the program is attached but did not evaluate real packets", seenBefore, seenAfter)
	}
	t.Logf("seen: %d -> %d", seenBefore, seenAfter)

	if loader.HasDenyRules() {
		if denyAfter <= denyBefore {
			t.Fatalf("would_deny counter did not increase for traffic to a denied destination: before=%d after=%d", denyBefore, denyAfter)
		}
		t.Logf("would_deny: %d -> %d", denyBefore, denyAfter)
	}
}

// TestDetachVeth_RemovesLink proves the cleanup path the daemon itself
// relies on when a container stops: after Detach, a fresh attach to the
// same ifindex must succeed again (a leaked/stuck link would make the
// second AttachVeth fail or silently no-op against the wrong program).
func TestDetachVeth_RemovesLink(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()

	ifindex, err := VethIndex(ebpfLoadHostVeth)
	if err != nil {
		t.Fatalf("VethIndex(%q): %v", ebpfLoadHostVeth, err)
	}

	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth: %v", err)
	}
	if err := loader.DetachVeth(ifindex); err != nil {
		t.Fatalf("DetachVeth: %v", err)
	}

	// Re-attach: only succeeds cleanly if Detach actually released the TCX
	// link rather than merely forgetting it in the Go-side map.
	if err := loader.AttachVeth(ifindex); err != nil {
		t.Fatalf("AttachVeth after Detach (link not actually released?): %v", err)
	}
	if err := loader.DetachVeth(ifindex); err != nil {
		t.Fatalf("final DetachVeth: %v", err)
	}
}

// A second, routed address on the host side of the veth pair. The netns (the
// "box") reaches it via the host-side veth address, so from the box's point of
// view it is a separate peer host — distinct from the host veth address, which
// plays the daemon. Outside the /30 so it cannot collide with either end.
const (
	ebpfLoadPeerBoxAddr = "10.250.112.1"
	// a2aPort mirrors internal/server's a2aPort (the in-box A2A server's
	// port). Duplicated rather than imported: internal/server imports this
	// package, and the value is part of the agent-runtime contract, not a knob.
	ebpfLoadA2APort   = 8674
	ebpfLoadOtherPort = 8675
)

// TestAttachedProgram_BoxCannotReachPeerA2APort is #2140's boundary, proven on
// a real kernel with real TCP rather than asserted on the compiled policy: a
// box whose policy is the agent-skill shape — the peer's /32 allowed, the
// daemon's address allowed (CONTAINARIUM_AGENT_EGRESS_CIDRS), and a tcp/8674
// deny on the peer — under ENFORCE
//
//   - cannot open a TCP connection to the peer's :8674,
//   - can still open one to any other port on the same peer (the /32 is kept),
//   - and the daemon (the host) can still open one to the box's own :8674 —
//     the only legitimate A2A path.
func TestAttachedProgram_BoxCannotReachPeerA2APort(t *testing.T) {
	loader, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() { _ = loader.Close() }()
	if !loader.HasDenyRules() {
		t.Fatal("object has no deny_cidr map — the A2A-port deny cannot be installed; rebuild netpolicy.bpf.o")
	}

	// Topology: a peer address on the host, routed from the box.
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); /* #nosec G204 -- fixed argv */ err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("ip", "addr", "add", ebpfLoadPeerBoxAddr+"/32", "dev", ebpfLoadHostVeth)
	t.Cleanup(func() {
		_ = exec.Command("ip", "addr", "del", ebpfLoadPeerBoxAddr+"/32", "dev", ebpfLoadHostVeth).Run() // #nosec G204 -- fixed argv
	})
	run("ip", "netns", "exec", ebpfLoadNetns, "ip", "route", "add", ebpfLoadPeerBoxAddr+"/32", "via", ebpfLoadHostAddr)

	// Listeners on the "peer" (host netns): its A2A port and some other port.
	for _, port := range []int{ebpfLoadA2APort, ebpfLoadOtherPort} {
		ln, err := net.Listen("tcp4", net.JoinHostPort(ebpfLoadPeerBoxAddr, fmt.Sprint(port)))
		if err != nil {
			t.Fatalf("listen on peer :%d: %v", port, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go acceptAndClose(ln)
	}

	// The box's policy, compiled through the same path the daemon uses.
	c, err := netpolicy.Compile(&pb.NetworkPolicy{
		Tenant:      "agent-caller",
		EgressCidrs: []string{ebpfLoadPeerBoxAddr + "/32", ebpfLoadHostAddr + "/32"},
		DenyRules:   []*pb.NetworkPolicyDenyRule{{Cidr: ebpfLoadPeerBoxAddr + "/32", Port: ebpfLoadA2APort, Proto: "tcp"}},
		Mode:        pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
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

	// Box -> peer: connect from inside the netns with bash's /dev/tcp (no
	// extra tooling on the runner). A dropped SYN shows up as a timeout.
	boxDial := func(port int) error {
		script := fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", ebpfLoadPeerBoxAddr, port)
		out, err := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv, constant script
			"timeout", "3", "bash", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	if err := boxDial(ebpfLoadOtherPort); err != nil {
		t.Fatalf("box -> peer :%d must still connect (the peer /32 is kept): %v", ebpfLoadOtherPort, err)
	}
	if err := boxDial(ebpfLoadA2APort); err == nil {
		t.Fatalf("box -> peer :%d connected; the A2A-port deny rule did not drop it", ebpfLoadA2APort)
	}

	// Daemon -> box: the host dials the box's own A2A port. A listener in the
	// netns (python3's stdlib server — present on the runner image) stands in
	// for the in-box A2A server.
	srv := exec.Command("ip", "netns", "exec", ebpfLoadNetns, // #nosec G204 -- fixed argv
		"python3", "-m", "http.server", fmt.Sprint(ebpfLoadA2APort), "--bind", ebpfLoadPeerAddr)
	if err := srv.Start(); err != nil {
		t.Fatalf("start in-netns listener: %v", err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	daemonAddr := net.JoinHostPort(ebpfLoadPeerAddr, fmt.Sprint(ebpfLoadA2APort))
	var dialErr error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var conn net.Conn
		conn, dialErr = net.DialTimeout("tcp4", daemonAddr, time.Second)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(200 * time.Millisecond) // listener still starting
	}
	if dialErr != nil {
		t.Fatalf("daemon -> box %s must connect (the deny is on the box's egress to peers, not on delivery to the box): %v", daemonAddr, dialErr)
	}
}

func acceptAndClose(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}
