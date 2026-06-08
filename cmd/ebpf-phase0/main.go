// Command ebpf-phase0 is the Go-side validator for the eBPF
// network isolation design's Phase 0.
//
// The shell-only validator (experimental/ebpf-phase0/validate.sh)
// confirms the kernel + Incus + tc-bpf path works. This binary
// confirms the production Go library — github.com/cilium/ebpf —
// can drive the same path end-to-end.
//
// If both Phase 0 validators pass on a Containarium backend,
// Phase A productionalizes. If this binary fails but the shell
// path passes, cilium/ebpf has an unexpected rough edge on the
// kernel + interface combination we target — investigate before
// committing to it in Phase A.
//
// THROWAWAY. Not for production. Run with --help for usage.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var (
		obj        = flag.String("obj", "experimental/ebpf-phase0/counter.bpf.o", "Path to the compiled counter.bpf.o")
		bridge     = flag.String("bridge", "incusbr0", "Bridge interface to attach to")
		watchEvery = flag.Duration("watch-every", 2*time.Second, "Counter print interval; 0 = once and exit")
	)
	flag.Parse()

	if err := run(*obj, *bridge, *watchEvery); err != nil {
		log.Fatalf("phase 0 go validator: %v", err)
	}
}

func run(objPath, bridge string, every time.Duration) error {
	// Bump memlock — older kernels need this for any BPF map
	// allocation. Kernel 5.11+ unified BPF memory into cgroup
	// accounting and the call is a no-op there, but it's free
	// insurance.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("RemoveMemlock: %w", err)
	}

	// Look up the bridge so we fail fast on a typo'd interface.
	iface, err := net.InterfaceByName(bridge)
	if err != nil {
		return fmt.Errorf("interface %q: %w", bridge, err)
	}

	// Resolve the BPF object path. Allow caller to pass a relative
	// path against the repo root for ergonomics.
	absObj, err := filepath.Abs(objPath)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", objPath, err)
	}
	if _, err := os.Stat(absObj); err != nil {
		return fmt.Errorf("BPF object %q: %w (build with `clang -O2 -g -target bpf -c counter.bpf.c -o counter.bpf.o`)", absObj, err)
	}

	spec, err := ebpf.LoadCollectionSpec(absObj)
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	defer coll.Close()

	ingressProg := coll.Programs["count_ingress"]
	egressProg := coll.Programs["count_egress"]
	counter := coll.Maps["pkt_counter"]
	if ingressProg == nil || egressProg == nil || counter == nil {
		return errors.New("BPF object missing expected program(s) or map (rebuild counter.bpf.o?)")
	}

	// Attach both programs via TCX. TCX is the modern tc-bpf
	// attach point (kernel ≥ 6.6) and is what cilium/ebpf's
	// link package supports first-class. Ubuntu 24.04 ships
	// 6.8 by default — fine for our target.
	//
	// If this returns ErrNotSupported, the kernel is too old
	// and the design's "kernel ≥ 5.4" floor in
	// docs/security/NETWORK-ISOLATION-DESIGN.md needs to be
	// revised upward to ≥ 6.6 (or Phase A picks netlink-based
	// classic tc attach instead).
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   ingressProg,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach ingress TCX: %w (kernel ≥ 6.6 required for link.AttachTCX; on older kernels, the design needs to use classic tc filter attach)", err)
	}
	defer func() { _ = ingressLink.Close() }()
	log.Printf("attached count_ingress to %s ingress (TCX)", bridge)

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   egressProg,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach egress TCX: %w", err)
	}
	defer func() { _ = egressLink.Close() }()
	log.Printf("attached count_egress to %s egress (TCX)", bridge)

	read := func() (in, eg uint64, err error) {
		var keyIn, keyEg uint32 = 0, 1
		if err := counter.Lookup(&keyIn, &in); err != nil {
			return 0, 0, fmt.Errorf("read ingress counter: %w", err)
		}
		if err := counter.Lookup(&keyEg, &eg); err != nil {
			return 0, 0, fmt.Errorf("read egress counter: %w", err)
		}
		return in, eg, nil
	}

	// Print initial counters so the operator has a baseline
	// before running any test traffic.
	in, eg, err := read()
	if err != nil {
		return err
	}
	log.Printf("initial: ingress=%d egress=%d", in, eg)

	if every == 0 {
		return nil
	}

	// Watch loop. Exit cleanly on SIGINT so deferred Close()
	// detaches both TCX links (otherwise they linger until the
	// kernel reaps them, which on TCX is "process exit" but
	// leaves a moment of confusion if you `tc filter show`).
	ctx := make(chan os.Signal, 1)
	signal.Notify(ctx, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(every)
	defer tick.Stop()
	log.Printf("watching every %s; ^C to detach + exit", every)
	for {
		select {
		case <-tick.C:
			in, eg, err := read()
			if err != nil {
				return err
			}
			log.Printf("ingress=%d egress=%d", in, eg)
		case sig := <-ctx:
			log.Printf("got %s; detaching and exiting", sig)
			return nil
		}
	}
}
