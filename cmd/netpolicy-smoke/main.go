// Command netpolicy-smoke is a throwaway end-to-end smoke test for the eBPF
// network-policy *enforcer* (#315 Phase A piece 6c). Where cmd/ebpf-phaseA
// exercises the bare loader, this drives the real server.NetworkPolicyEnforcer:
// it constructs the enforcer with an in-memory policy store + tenant registry +
// a real Incus client, seeds a policy for a test tenant, then Start()s it so the
// enforcer's own reconcile loop discovers the live container, resolves its veth,
// populates the BPF maps, attaches the program, and runs the perf consumer.
//
// Run it on a backend, create a `<tenant>-container`, generate traffic, and
// watch the enforcer log "would-deny" lines for flows outside the seeded
// allow-list (and stay silent for flows inside it). Observation-only — nothing
// is dropped.
//
// THROWAWAY. Not built into releases. Run with --help.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/server"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type cidrList []string

func (c *cidrList) String() string { return "" }
func (c *cidrList) Set(v string) error {
	*c = append(*c, v)
	return nil
}

func main() {
	var (
		obj        = flag.String("obj", "netpolicy.bpf.o", "Path to the compiled netpolicy.bpf.o")
		tenant     = flag.String("tenant", "smoketest", "Tenant to seed a policy for (container must be <tenant>-container)")
		allowIntra = flag.Bool("allow-intra", false, "Allow same-tenant intra-backend traffic")
		enforce    = flag.Bool("enforce", false, "Arm enforcement: seed an enforce-mode policy and let the enforcer DROP denied flows (Phase B). Default off = observation-only.")
		allowMeta  = flag.Bool("allow-metadata", false, "Allow the cloud metadata service 169.254.169.254 (Phase D); default deny")
	)
	var allow cidrList
	flag.Var(&allow, "allow-cidr", "Allowed egress CIDR (repeatable)")
	var allowDomain cidrList
	flag.Var(&allowDomain, "allow-domain", "Allowed egress domain, resolved to IPs (repeatable, Phase C)")
	flag.Parse()

	incusClient, err := incus.New()
	if err != nil {
		log.Fatalf("incus client: %v", err)
	}

	// Seed an in-memory policy for the test tenant.
	mode := pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	if *enforce {
		mode = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	}
	store := server.NewMemNetworkPolicyStore()
	if err := store.Set(context.Background(), &pb.NetworkPolicy{
		Tenant:           *tenant,
		AllowIntraTenant: *allowIntra,
		EgressCidrs:      []string(allow),
		EgressDomains:    []string(allowDomain),
		AllowMetadata:    *allowMeta,
		Mode:             mode,
	}); err != nil {
		log.Fatalf("seed policy: %v", err)
	}
	log.Printf("seeded policy: tenant=%q mode=%v allow_intra=%v egress_cidrs=%v egress_domains=%v",
		*tenant, mode, *allowIntra, []string(allow), []string(allowDomain))

	// Real enforcer: Mem store + Mem registry + real Incus + no audit store
	// (would-deny flows surface as log lines via OnDenyEvent) + the global bus.
	// The last arg arms enforcement (drops); off = observation-only.
	enforcer := server.NewNetworkPolicyEnforcer(*obj, store, server.NewMemTenantRegistry(), incusClient, nil, events.GetBus(), *enforce)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := enforcer.Start(ctx); err != nil {
		log.Fatalf("enforcer start: %v", err)
	}
	log.Printf("enforcer running; create %s-container, generate traffic, watch for would-deny lines. ^C to stop.", *tenant)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("stopping enforcer (detaching)...")
	cancel()
	enforcer.Stop()
	time.Sleep(200 * time.Millisecond)
}
