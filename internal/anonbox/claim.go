package anonbox

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/box"
)

// Claim errors. The RPC layer maps them: AlreadyClaimed → AlreadyExists,
// Expired → FailedPrecondition, Invalid → PermissionDenied, NotFound →
// NotFound. Anything else is Internal.
var (
	ErrClaimAlreadyClaimed = errors.New("anonbox: box already claimed")
	ErrClaimExpired        = errors.New("anonbox: claim token expired")
	ErrClaimInvalid        = errors.New("anonbox: claim token invalid")
	ErrClaimNotFound       = errors.New("anonbox: box not found")
)

// LabelClaimedBy records the tenant that redeemed the token, beside
// LabelClaimedAt, so an operator can read both off the box.
const LabelClaimedBy = "anon.claimed_by"

// ClaimRequest is one redemption.
type ClaimRequest struct {
	Token          string
	Tenant         string   // new owner's username
	AuthorizedKeys []string // the tenant's keys to add; the claiming key stays
}

// ClaimResult is what a successful redemption changed.
type ClaimResult struct {
	BoxName string
	Tenant  string
	SSHUser string // unchanged: the box's own login, reached through the door
}

// tenantRe is the username shape every other tenant obeys.
var tenantRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Claim binds a box to a tenant via its single-use token (decision on
// #2199: the door path is kept — the box keeps its name and login and is
// still reached via `ssh new.<domain>` with the claiming key, now with no
// TTL; no jump account is created because normal routing could never
// reach a box named anon-<fp8>-container).
//
// Order matters: the claimed_at compare-and-set comes first so two
// concurrent redemptions cannot both convert the box; the conversion
// steps after it are idempotent, so a failure there leaves a box that is
// marked claimed and can be finished by an operator, never one that two
// tenants own.
func (m *Manager) Claim(ctx context.Context, req ClaimRequest) (*ClaimResult, error) {
	if !tenantRe.MatchString(req.Tenant) {
		return nil, InvalidRequestError{Err: fmt.Errorf("anonbox: invalid tenant %q", req.Tenant)}
	}
	if m.cfg.ClaimSecret == nil {
		return nil, errors.New("anonbox: claims are not enabled on this daemon (no claim secret)")
	}
	parsed, err := ParseClaimToken(req.Token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimInvalid, err)
	}
	st, err := m.findByName(ctx, parsed.BoxName)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Labels[LabelFingerprint] == "" {
		return nil, ErrClaimNotFound
	}
	tok, err := VerifyClaimToken(m.cfg.ClaimSecret(parsed.BoxName), req.Token, m.cfg.Now())
	switch {
	case errors.Is(err, ErrTokenExpired):
		return nil, ErrClaimExpired
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrClaimInvalid, err)
	}
	if tok.TokenID != st.Labels[LabelClaimTokenID] || tok.FPHash != st.Labels[LabelFPHash] {
		return nil, fmt.Errorf("%w: token does not belong to this box", ErrClaimInvalid)
	}

	// The LXC backend derives the container AND its Linux user from
	// ref.Tenant, so every write below addresses the box by its own name
	// — not by the tenant it is about to belong to.
	ref := boxRefFor(st.Ref.Name)
	now := m.cfg.Now()

	m.claimMu.Lock()
	defer m.claimMu.Unlock()
	if st.Labels[LabelClaimedAt] != "" {
		return nil, ErrClaimAlreadyClaimed
	}
	// Re-read under the lock: the List above was unlocked.
	if cur, err := m.findByName(ctx, ref.Name); err != nil {
		return nil, err
	} else if cur == nil {
		return nil, ErrClaimNotFound
	} else if cur.Labels[LabelClaimedAt] != "" {
		return nil, ErrClaimAlreadyClaimed
	}
	if err := m.boxes.SetMeta(ctx, ref, map[string]string{
		LabelClaimedAt: now.UTC().Format(time.RFC3339),
		LabelClaimedBy: req.Tenant,
	}); err != nil {
		return nil, fmt.Errorf("anonbox: mark %s claimed: %w", ref.Name, err)
	}

	var errs []error
	if err := m.boxes.SetTTL(ctx, ref, nil); err != nil {
		errs = append(errs, fmt.Errorf("clear ttl: %w", err))
	}
	if err := m.liftEgressGuard(ref.Name); err != nil {
		errs = append(errs, fmt.Errorf("lift egress guard: %w", err))
	}
	keys := dedupeKeys(append([]string{st.Labels[LabelPublicKey]}, req.AuthorizedKeys...))
	if err := m.boxes.SetAuthorizedKeys(ctx, ref, keys); err != nil {
		errs = append(errs, fmt.Errorf("set authorized keys: %w", err))
	}
	// Ownership last: once the tenant label is set, status reports the
	// box under the new tenant, and the writes above must already have
	// gone to the right container.
	if err := m.boxes.SetOwner(ctx, ref, req.Tenant); err != nil {
		errs = append(errs, fmt.Errorf("set owner: %w", err))
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("anonbox: %s claimed by %s but conversion incomplete: %w", ref.Name, req.Tenant, errors.Join(errs...))
	}
	m.record(FunnelEvent{Kind: FunnelClaimCompleted, FPHash: st.Labels[LabelFPHash], BoxName: ref.Name})
	return &ClaimResult{BoxName: ref.Name, Tenant: req.Tenant, SSHUser: ref.Tenant}, nil
}

// findByName returns the box with that instance name, or nil.
func (m *Manager) findByName(ctx context.Context, name string) (*box.BoxStatus, error) {
	all, err := m.boxes.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("anonbox: list boxes: %w", err)
	}
	for i := range all {
		if all[i].Ref.Name == name {
			return &all[i], nil
		}
	}
	return nil, nil
}

// boxRefFor addresses a box by its own name on backends that derive the
// container (and login) from ref.Tenant.
func boxRefFor(name string) box.BoxRef {
	return box.BoxRef{Tenant: strings.TrimSuffix(name, "-container"), Name: name}
}

func dedupeKeys(keys []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}
