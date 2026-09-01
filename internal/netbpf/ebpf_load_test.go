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
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
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
