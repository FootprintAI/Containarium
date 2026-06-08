// Command ebpf-phaseA is the on-backend validator for Phase A of the eBPF
// network-isolation design (docs/security/NETWORK-ISOLATION-DESIGN.md, #315).
//
// Where cmd/ebpf-phase0 proved a bare counter attaches and sees traffic, this
// binary exercises the real Phase A pieces end-to-end against a live container
// veth:
//
//   - load the policy program + maps (internal/netbpf.Load)
//   - install a per-tenant policy (config + egress allow-list + peer IPs)
//   - attach to a container's host veth in TC_INGRESS
//   - watch the seen / would-deny counters and drain the denied-flow perf ring
//
// Phase A is OBSERVATION ONLY: nothing is dropped; would-deny flows are merely
// counted and emitted. Run it on a backend, generate traffic from the target
// container, and confirm the counters + events match expectations.
//
// THROWAWAY / operator tool. Not wired into the daemon. Run with --help.
//
// Build the BPF object first (on the backend):
//
//	clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
//	    -c experimental/ebpf-phaseA/netpolicy.bpf.c -o netpolicy.bpf.o
package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/perf"

	"github.com/footprintai/containarium/internal/netbpf"
)

type cidrList []string

func (c *cidrList) String() string { return fmt.Sprint(*c) }
func (c *cidrList) Set(v string) error {
	*c = append(*c, v)
	return nil
}

func main() {
	var (
		obj        = flag.String("obj", "netpolicy.bpf.o", "Path to the compiled netpolicy.bpf.o")
		veth       = flag.String("veth", "", "Host veth interface name to attach to (required)")
		tenant     = flag.Uint("tenant", 1, "Tenant ID to assign to the veth's policy")
		allowIntra = flag.Bool("allow-intra", false, "Allow same-tenant intra-backend traffic")
		peerIP     = flag.String("peer-ip", "", "A managed peer container IP to register (optional)")
		peerTenant = flag.Uint("peer-tenant", 1, "Tenant ID for --peer-ip")
		every      = flag.Duration("watch-every", 2*time.Second, "Counter print interval")
	)
	var allow cidrList
	flag.Var(&allow, "allow-cidr", "Allowed egress CIDR (repeatable, e.g. --allow-cidr 8.8.8.8/32)")
	flag.Parse()

	if *veth == "" {
		log.Fatal("phase A validator: --veth is required")
	}
	if err := run(*obj, *veth, uint32(*tenant), *allowIntra, allow, *peerIP, uint32(*peerTenant), *every); err != nil {
		log.Fatalf("phase A validator: %v", err)
	}
}

func run(objPath, veth string, tenant uint32, allowIntra bool, allow cidrList, peerIP string, peerTenant uint32, every time.Duration) error {
	ifindex, err := netbpf.VethIndex(veth)
	if err != nil {
		return err
	}

	loader, err := netbpf.Load(objPath)
	if err != nil {
		return err
	}
	defer func() { _ = loader.Close() }()

	// Per-veth policy config (log-only for Phase A).
	cfg := netbpf.PolicyConfig{TenantID: tenant, Mode: netbpf.ModeLogOnly}
	if allowIntra {
		cfg.AllowIntra = 1
	}
	if err := loader.SetVethPolicy(ifindex, cfg); err != nil {
		return err
	}

	for _, c := range allow {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("parse --allow-cidr %q: %w", c, err)
		}
		if !p.Addr().Is4() {
			return fmt.Errorf("--allow-cidr %q is not IPv4 (Phase A is IPv4-only)", c)
		}
		p = p.Masked()
		if err := loader.AddEgress(netbpf.EgressEntry{
			PrefixLen: 32 + uint32(p.Bits()),
			TenantID:  tenant,
			Addr:      p.Addr().As4(),
		}); err != nil {
			return err
		}
		log.Printf("egress allow: tenant=%d %s", tenant, p)
	}

	if peerIP != "" {
		a, err := netip.ParseAddr(peerIP)
		if err != nil || !a.Is4() {
			return fmt.Errorf("--peer-ip %q must be an IPv4 address", peerIP)
		}
		if err := loader.SetIPTenant(a.As4(), peerTenant); err != nil {
			return err
		}
		log.Printf("peer registered: %s -> tenant=%d", peerIP, peerTenant)
	}

	if err := loader.AttachVeth(ifindex); err != nil {
		return err
	}
	log.Printf("attached netpolicy to %s (ifindex %d), tenant=%d allow_intra=%v mode=log_only",
		veth, ifindex, tenant, allowIntra)

	// Drain the denied-flow perf ring in the background.
	rd, err := perf.NewReader(loader.EventsMap(), os.Getpagesize())
	if err != nil {
		return fmt.Errorf("open perf reader: %w", err)
	}
	defer func() { _ = rd.Close() }()
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return // reader closed on exit
			}
			if rec.LostSamples > 0 {
				log.Printf("perf: lost %d samples", rec.LostSamples)
				continue
			}
			ev, err := netbpf.ParseDenyEvent(rec.RawSample)
			if err != nil {
				log.Printf("perf: decode: %v", err)
				continue
			}
			log.Printf("WOULD-DENY src=%s dst=%s proto=%d dport=%d (tenant=%d ifindex=%d)",
				ev.Src(), ev.Dst(), ev.Proto, ev.Dport, ev.TenantID, ev.Ifindex)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(every)
	defer tick.Stop()
	log.Printf("watching every %s; ^C to detach + exit", every)
	for {
		select {
		case <-tick.C:
			seen, deny, err := loader.Stats()
			if err != nil {
				return err
			}
			log.Printf("seen=%d would_deny=%d", seen, deny)
		case s := <-sig:
			log.Printf("got %s; detaching and exiting", s)
			return nil
		}
	}
}
