// Package pool implements the warm-pool reconciler and claim ring for
// ephemeral sandboxes (#1488 Phase 3): "Pool members are created and
// started by a background reconciler. A claim touches an instance that
// has been running for seconds to minutes" instead of paying boot cost on
// the request path.
//
// A pool member is a whole Incus container, dedicated to exactly one
// task, destroyed on release and never reused — see Release's doc
// comment and the design note's Isolation section for why. Ready members
// are tracked per SandboxTemplate ("shared" means shared across tenants,
// not across templates): v1 configures the base template only.
//
// This package talks to the same incus.Backend-shaped interface
// SandboxServer (internal/server/sandbox_server.go) already uses to
// create/destroy sandboxes directly — not pkg/core/container.Manager or
// box.BoxBackend, both of which are built around the full persistent-box
// identity flow (SSH keys, tenant naming) that pool members, like cold-
// path sandboxes, explicitly skip. A pool member and a cold-path sandbox
// should be indistinguishable in shape once claimed.
//
// Pure Go control-plane state plus calls to a narrow, fakeable Backend
// interface — no live Incus host needed to build or test this package,
// per the design note's own scoping ("pool logic tests run in
// milliseconds with no host"). The nightly latency test against a real
// host is Phase 3's actual exit criterion and lives elsewhere.
package pool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/sandbox/ipam"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Backend is the subset of incus.Backend the pool reconciler needs to
// warm and destroy members. Any concrete type satisfying incus.Backend
// (in particular *incus.Client, the real thing) automatically satisfies
// this narrower interface too — no adapter required — while a test fake
// only has to implement four methods instead of incus.Backend's full
// surface.
type Backend interface {
	CreateContainer(config incus.ContainerConfig) error
	StartContainer(name string) error
	StopContainer(name string, force bool) error
	DeleteContainer(name string) error
}

// ErrPoolExhausted is returned by Claim when no ready member exists for
// the requested template.
var ErrPoolExhausted = errors.New("pool: no ready member for this template")

// Member is the pool's typed view of one pool member — a named struct,
// not the map[string]string the design note's Contracts section
// specifically calls out as the wrong shape for this.
type Member struct {
	ID       string
	Template pb.SandboxTemplate
	IP       string
	WarmedAt time.Time
}

// Config controls what Reconcile keeps warm.
type Config struct {
	// MinWarm is the target ready-member count, per template. A template
	// with no entry (or 0) is never warmed — v1 configures BASE only.
	MinWarm map[pb.SandboxTemplate]int
	// Image maps a template to the guest image a warm-up clones from.
	// Required for every template named in MinWarm.
	Image map[pb.SandboxTemplate]string
	// NICNetwork is the Incus bridged network warm members attach to
	// (e.g. "incusbr0"), paired with a static IPAM-allocated address so
	// WaitForNetwork's DHCP wait happens at warm time, not claim time.
	NICNetwork string
}

// Pool holds the ready ring and in-flight warm counts, one per template,
// and reconciles them against Config.MinWarm. Safe for concurrent use —
// Claim and Reconcile share one mutex, so a claim during reconcile always
// sees a consistent ring, never a torn one.
type Pool struct {
	backend Backend
	ipam    *ipam.Allocator
	cfg     Config

	mu      sync.Mutex
	ready   map[pb.SandboxTemplate][]*Member // FIFO ring per template
	warming map[pb.SandboxTemplate]int       // in-flight warm count per template
}

// New builds a Pool. cfg is copied defensively (the maps are read, not
// retained by reference) so a caller mutating its own Config after New
// doesn't reach back into the Pool.
func New(backend Backend, allocator *ipam.Allocator, cfg Config) *Pool {
	minWarm := make(map[pb.SandboxTemplate]int, len(cfg.MinWarm))
	for k, v := range cfg.MinWarm {
		minWarm[k] = v
	}
	image := make(map[pb.SandboxTemplate]string, len(cfg.Image))
	for k, v := range cfg.Image {
		image[k] = v
	}

	return &Pool{
		backend: backend,
		ipam:    allocator,
		cfg:     Config{MinWarm: minWarm, Image: image, NICNetwork: cfg.NICNetwork},
		ready:   make(map[pb.SandboxTemplate][]*Member),
		warming: make(map[pb.SandboxTemplate]int),
	}
}

// Claim removes and returns the next ready member for template, O(1). A
// claimed member leaves the pool's bookkeeping entirely — the caller owns
// its lifecycle from here, and Release (below) is the only path back to
// this package, which always destroys rather than re-adding it.
func (p *Pool) Claim(template pb.SandboxTemplate) (*Member, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ring := p.ready[template]
	if len(ring) == 0 {
		return nil, ErrPoolExhausted
	}
	m := ring[0]
	// Keep the backing array from retaining a reference to a claimed
	// member forever (ring[0] = nil before reslicing) — small pool
	// sizes make this immaterial in practice, but it's free to do right.
	ring[0] = nil
	p.ready[template] = ring[1:]
	return m, nil
}

// Release destroys member. This function's entire body is "destroy, full
// stop" — a pool member is dedicated to exactly one task and is never
// reset and returned to the ready ring (see the design note's Isolation
// section: reuse is what turns a shared pool from isolation-equivalent-
// to-per-tenant into a cross-tenant data-leak vector). TestDestroyOnRelease
// exists specifically to fail loudly if anyone ever adds a reset-and-
// reuse path here — don't.
//
// Unlike the reconciler's own trim (best-effort, logged, never blocks a
// caller), Release propagates a real failure: the caller asked this
// member destroyed and needs to know if that didn't happen.
func (p *Pool) Release(m *Member) error {
	return p.destroy(m)
}

// ReadyCount returns how many members are currently claimable for
// template. For GetPoolStatus / operator visibility, not used by Claim
// itself (which must stay a single atomic pop, not a check-then-act).
func (p *Pool) ReadyCount(template pb.SandboxTemplate) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready[template])
}

// TemplateStatus is one template's pool state, for operator visibility
// (SandboxServer.GetPoolStatus, #1488 Phase 4). A named struct rather than
// a positional tuple or map — see the design note's Contracts section on
// why this package favors typed views over "was it templates[i][0] or
// [1]?" ambiguity.
type TemplateStatus struct {
	Template pb.SandboxTemplate
	// Ready is how many members are claimable right now (same count
	// ReadyCount reports for this template).
	Ready int
	// Warming is how many members are being created/started/network-
	// provisioned, not yet claimable.
	Warming int
	// MinWarm is the operator-configured floor Ready+Warming is being
	// reconciled toward.
	MinWarm int
}

// Status returns one TemplateStatus per template configured in
// Config.MinWarm, sorted by template value for a deterministic result —
// an operator diagnosing "why is my pool empty" needs to see the
// configured floor even when Ready and Warming are both zero, so this
// reports every configured template rather than only ones with current
// ready/warming activity.
func (p *Pool) Status() []TemplateStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	statuses := make([]TemplateStatus, 0, len(p.cfg.MinWarm))
	for template, minWarm := range p.cfg.MinWarm {
		statuses = append(statuses, TemplateStatus{
			Template: template,
			Ready:    len(p.ready[template]),
			Warming:  p.warming[template],
			MinWarm:  minWarm,
		})
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Template < statuses[j].Template })
	return statuses
}

// Reconcile brings every configured template's ready+warming count to
// Config.MinWarm: short → start warming the difference; over (ready
// alone; in-flight warms are never aborted mid-boot) → trim the excess,
// oldest first. Call periodically (the caller owns the schedule — this
// package has no ticker of its own).
//
// State mutation (deciding what to warm/trim) happens under the mutex;
// the actual I/O (CreateContainer, DeleteContainer, ...) happens after
// releasing it, so a slow Incus call never blocks a concurrent Claim. A
// warm that fails is simply not added to the ready ring — the next
// Reconcile call sees the same shortfall and retries. That's this
// package's entire backoff mechanism: retry cadence is the caller's
// polling interval, not a per-member timer, so one wedged member can
// never block reconciling any other template.
func (p *Pool) Reconcile(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	toWarm, toTrim := p.planLocked()

	var wg sync.WaitGroup
	for _, template := range toWarm {
		wg.Add(1)
		go func(t pb.SandboxTemplate) {
			defer wg.Done()
			p.warmOne(ctx, t)
		}(template)
	}
	for _, m := range toTrim {
		wg.Add(1)
		go func(m *Member) {
			defer wg.Done()
			if err := p.destroy(m); err != nil {
				log.Printf("[pool] trim of idle member %s failed (will be retried next reconcile? no — it already left the ring; logged only): %v", m.ID, err)
			}
		}(m)
	}
	wg.Wait()
}

// planLocked snapshots this tick's deltas and commits the bookkeeping
// side of them (warming counters incremented, trimmed members removed
// from the ring) before any I/O runs. Named *Locked per this package's
// convention for a helper that must be called with p.mu held — it takes
// the lock itself and returns after releasing it, so callers just call it
// plainly; the suffix documents that it does its own locking rather than
// assuming a lock inherited from the caller.
func (p *Pool) planLocked() (toWarm []pb.SandboxTemplate, toTrim []*Member) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for template, target := range p.cfg.MinWarm {
		readyCount := len(p.ready[template])
		total := readyCount + p.warming[template]

		switch {
		case total < target:
			short := target - total
			for i := 0; i < short; i++ {
				toWarm = append(toWarm, template)
			}
			p.warming[template] += short
		case readyCount > target:
			excess := readyCount - target
			toTrim = append(toTrim, p.ready[template][:excess]...)
			p.ready[template] = p.ready[template][excess:]
		}
	}
	return toWarm, toTrim
}

// warmOne creates, starts, and IP-provisions one new member for template,
// adding it to the ready ring only on full success. Any failure at any
// step unwinds what that step already did and leaves the ready ring
// untouched — the shortfall this warm was meant to cover is picked back
// up by the next Reconcile call.
func (p *Pool) warmOne(ctx context.Context, template pb.SandboxTemplate) {
	defer func() {
		p.mu.Lock()
		p.warming[template]--
		p.mu.Unlock()
	}()

	image, ok := p.cfg.Image[template]
	if !ok {
		log.Printf("[pool] warm %v: no image configured for this template", template)
		return
	}

	id, err := newMemberID()
	if err != nil {
		log.Printf("[pool] warm %v: %v", template, err)
		return
	}

	ip, err := p.ipam.Allocate()
	if err != nil {
		log.Printf("[pool] warm %v (%s): ipam: %v", template, id, err)
		return
	}

	config := incus.ContainerConfig{
		Name:  id,
		Image: image,
		NIC: &incus.NICDevice{
			Name:        "eth0",
			Network:     p.cfg.NICNetwork,
			IPv4Address: ip.String(),
		},
	}

	if err := p.backend.CreateContainer(config); err != nil {
		_ = p.ipam.Release(ip)
		log.Printf("[pool] warm %v (%s): create: %v", template, id, err)
		return
	}
	if err := p.backend.StartContainer(id); err != nil {
		_ = p.backend.DeleteContainer(id)
		_ = p.ipam.Release(ip)
		log.Printf("[pool] warm %v (%s): start: %v", template, id, err)
		return
	}

	m := &Member{ID: id, Template: template, IP: ip.String(), WarmedAt: time.Now()}
	p.mu.Lock()
	p.ready[template] = append(p.ready[template], m)
	p.mu.Unlock()
}

// destroy stops (force, errors ignored) then deletes m, releasing its
// IPAM allocation regardless of the delete outcome — a failed delete
// shouldn't also leak the address. Returns the delete error, if any.
func (p *Pool) destroy(m *Member) error {
	_ = p.backend.StopContainer(m.ID, true)
	deleteErr := p.backend.DeleteContainer(m.ID)

	if ip := net.ParseIP(m.IP); ip != nil {
		if err := p.ipam.Release(ip); err != nil {
			log.Printf("[pool] destroy %s: ipam release: %v", m.ID, err)
		}
	}

	if deleteErr != nil {
		return fmt.Errorf("destroy %s: %w", m.ID, deleteErr)
	}
	return nil
}

// memberNamePrefix and newMemberID match sandbox_server.go's own
// sandbox-<hex> naming exactly (duplicated, not shared, across the two
// packages — three lines isn't worth a shared micro-package, and a pool
// member's ID must be indistinguishable in shape from a cold-path
// sandbox_id: once claimed, from the caller's perspective, it just is
// one).
const memberNamePrefix = "sandbox-"

func newMemberID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate pool member id: %w", err)
	}
	return memberNamePrefix + hex.EncodeToString(b), nil
}
