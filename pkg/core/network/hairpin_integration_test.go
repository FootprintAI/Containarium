//go:build incus

// Real-kernel hairpin coverage for the Caddy port-forward (#2732, slice A of
// #2263). Needs root, `ip` and `iptables`, so it rides the existing privileged
// lane (.github/workflows/incus-create.yml, -tags=incus, run under sudo, with
// CONTAINARIUM_REQUIRE_INCUS=1 turning a skip into a failure). It does not use
// Incus itself.
//
// Everything happens inside throwaway network namespaces; the runner's own
// netns and firewall are never touched:
//
//	hpb (box, 10.251.0.10) ─┐
//	                        ├─ br0 (10.251.0.1/24) ─ hph (host) ─ up0 ─ hpu (upstream, 203.0.113.2)
//	hpc (caddy, 10.251.0.2) ┘   pub0 (198.51.100.10/32): the host's own "public" address
package network

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
)

const (
	hpHost, hpBox, hpCaddy, hpUp = "hph", "hpb", "hpc", "hpu"
	hpCaddyIP                    = "10.251.0.2"
	hpPublicIP                   = "198.51.100.10"
	hpUpstreamIP                 = "203.0.113.2"
)

// A box on the bridge opening the host's own address on 80/443 must reach
// Caddy through the kernel, and a box opening some other address on 443 must
// not be redirected. The first phase installs the pre-#2732 rule shape and
// proves the hairpin fails with it, so this test can fail.
func TestIntegrationHairpinBridgeClientReachesCaddy(t *testing.T) {
	if os.Geteuid() != 0 {
		if incusenv.DispositionFor(os.Getenv(incusenv.RequireEnv)) == incusenv.Fail {
			t.Fatalf("hairpin test needs root (%s is set, so this is a failure)", incusenv.RequireEnv)
		}
		t.Skip("hairpin test needs root; run with sudo -E -tags=incus")
	}
	setupHairpinTopology(t)
	ipt := func(args ...string) string {
		return hpRun(t, append([]string{"ip", "netns", "exec", hpHost, "iptables"}, args...)...)
	}

	hpServe(t, hpCaddy, hpCaddyIP+":80", "caddy")
	hpServe(t, hpCaddy, hpCaddyIP+":443", "caddy")
	hpServe(t, hpUp, hpUpstreamIP+":443", "upstream")

	// Phase 1: the old shape. Bridge traffic is excluded, so the box's
	// connection to the host's own address is never DNAT'd.
	for _, p := range []string{"80", "443"} {
		ipt("-t", "nat", "-A", "PREROUTING", "!", "-s", "10.251.0.0/24", "-p", "tcp", "--dport", p,
			"-j", "DNAT", "--to-destination", hpCaddyIP+":"+p)
	}
	ipt("-t", "nat", "-A", "POSTROUTING", "-d", hpCaddyIP, "-j", "MASQUERADE")
	if got, err := hpDial(hpBox, hpPublicIP+":443"); err == nil {
		t.Fatalf("legacy shape unexpectedly hairpinned (got %q); the test cannot tell the shapes apart", got)
	}

	// Phase 2: what SetupPortForwarding does on upgrade — clear the old
	// shape from real `iptables -S` output, then install the new rule.
	for _, del := range caddyNATRulesToClear(ipt("-t", "nat", "-S"), hpCaddyIP) {
		ipt(del...)
	}
	if left := ipt("-t", "nat", "-S", "PREROUTING"); strings.Contains(left, "! -s") {
		t.Fatalf("legacy rule survived reconciliation:\n%s", left)
	}
	for _, p := range []int{80, 443} {
		ipt(append([]string{"-t", "nat", "-A"}, caddyPreRoutingRule(p, hpCaddyIP)...)...)
	}

	for _, p := range []string{"80", "443"} {
		got, err := hpDial(hpBox, hpPublicIP+":"+p)
		if err != nil || got != "caddy" {
			t.Errorf("box -> host's own address :%s: got %q, err %v; want DNAT to caddy\n%s", p, got, err, ipt("-t", "nat", "-S"))
		}
	}
	if got, err := hpDial(hpBox, hpUpstreamIP+":443"); err != nil || got != "upstream" {
		t.Errorf("box -> non-local address :443: got %q, err %v; want the upstream, not caddy", got, err)
	}
}

func setupHairpinTopology(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, ns := range []string{hpHost, hpBox, hpCaddy, hpUp} {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	for _, ns := range []string{hpHost, hpBox, hpCaddy, hpUp} {
		_ = exec.Command("ip", "netns", "del", ns).Run() // leftovers from an aborted run
		hpRun(t, "ip", "netns", "add", ns)
		hpRun(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	h := func(args ...string) { hpRun(t, append([]string{"ip", "-n", hpHost}, args...)...) }
	h("link", "add", "br0", "type", "bridge")
	h("addr", "add", "10.251.0.1/24", "dev", "br0")
	h("link", "set", "br0", "up")
	h("link", "add", "pub0", "type", "dummy")
	h("addr", "add", hpPublicIP+"/32", "dev", "pub0")
	h("link", "set", "pub0", "up")
	hpRun(t, "ip", "netns", "exec", hpHost, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	for _, peer := range []struct{ ns, hostIf, addr, gw, viaBridge string }{
		{hpBox, "vb", "10.251.0.10/24", "10.251.0.1", "br0"},
		{hpCaddy, "vc", hpCaddyIP + "/24", "10.251.0.1", "br0"},
		{hpUp, "up0", hpUpstreamIP + "/24", "203.0.113.1", ""},
	} {
		h("link", "add", peer.hostIf, "type", "veth", "peer", "name", "eth0", "netns", peer.ns)
		if peer.viaBridge != "" {
			h("link", "set", peer.hostIf, "master", peer.viaBridge)
		} else {
			h("addr", "add", "203.0.113.1/24", "dev", peer.hostIf)
		}
		h("link", "set", peer.hostIf, "up")
		hpRun(t, "ip", "-n", peer.ns, "addr", "add", peer.addr, "dev", "eth0")
		hpRun(t, "ip", "-n", peer.ns, "link", "set", "eth0", "up")
		hpRun(t, "ip", "-n", peer.ns, "route", "add", "default", "via", peer.gw)
	}
}

func hpRun(t *testing.T, argv ...string) string {
	t.Helper()
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- fixed test commands
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(argv, " "), err, out)
	}
	return string(out)
}

// inNetns runs fn on an OS thread switched into the named netns. Sockets
// keep the netns they were created in, so a listener opened here keeps
// serving there after the thread switches back.
func inNetns(ns string, fn func() error) error {
	runtime.LockOSThread()
	orig, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer orig.Close()
	target, err := os.Open("/var/run/netns/" + ns)
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	ferr := fn()
	if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("restore netns: %w", err) // thread stays locked and dies with its goroutine
	}
	runtime.UnlockOSThread()
	return ferr
}

// hpServe answers every connection on addr inside ns with name.
func hpServe(t *testing.T, ns, addr, name string) {
	t.Helper()
	var ln net.Listener
	if err := inNetns(ns, func() (err error) { ln, err = net.Listen("tcp", addr); return }); err != nil {
		t.Fatalf("listen %s in %s: %v", addr, ns, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, name)
			_ = c.Close()
		}
	}()
}

// hpDial connects to addr from inside ns and returns what the server said.
func hpDial(ns, addr string) (string, error) {
	var c net.Conn
	if err := inNetns(ns, func() (err error) { c, err = net.DialTimeout("tcp", addr, 3*time.Second); return }); err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := io.ReadAll(c)
	return string(b), err
}
