// Package anonbox is the daemon side of the `ssh new.<cloud-domain>` door
// (docs/architecture/ssh-new-anonymous-box.md, #2197): it owns the
// SSH-key-fingerprint → VM mapping for anonymous boxes.
//
// An anonymous box is an ordinary Containarium box with three differences
// the Manager enforces on every create: it is an Incus VM (never a
// shared-kernel container), it is born with a TTL, and its NIC carries an
// egress ACL that drops everything but DNS, HTTP and HTTPS. Its state —
// which fingerprint it belongs to, when it was created, its claim token id
// — lives in the box's own labels, the same place TTL and auto-sleep state
// already live, so there is no second store to drift from Incus.
//
// The Manager is pure control logic over two narrow, fakeable seams (Boxes,
// ACLs); wiring it to the real box backend and Incus client, and exposing
// it as AnonymousBoxService, is the follow-up PR on the same issue.
// Rate limits, the global cap, the kill switch and bans are #2200; the
// claim token itself is #2199 (the ClaimURL hook is its seam).
package anonbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lxc/incus/v7/shared/api"
	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/internal/sandbox/ratelimit"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Label keys stamped on an anonymous box. They ride the normal label
// mechanism (user.containarium.label.<key> in Incus) so BoxStatus.Labels
// carries them back on List/Get without a new read path.
const (
	LabelFingerprint  = "anon.fingerprint"    // "SHA256:…" — the lookup key; one live box per value
	LabelFPHash       = "anon.fp_hash"        // sha256 hex of the fingerprint (what events carry)
	LabelCreatedAt    = "anon.created_at"     // RFC3339
	LabelSourceIP     = "anon.source_ip"      // retained for abuse handling; dies with the box
	LabelClaimTokenID = "anon.claim_token_id" // random 16 B hex, embedded in the claim token (#2199)
	LabelClaimedAt    = "anon.claimed_at"     // empty until claimed; the CAS target of #2199
	LabelPublicKey    = "anon.public_key"     // the claiming key's authorized_keys line, kept on claim
)

// In-guest paths the Manager writes.
const (
	ClaimURLPath = "/etc/containarium/claim-url"
	BannerPath   = "/etc/update-motd.d/50-containarium-anon"
)

// Limits are the fixed per-box caps and the birth TTL. Fixed, not
// per-request: an anonymous caller does not get to pick.
type Limits struct {
	CPU    string
	Memory string
	Disk   string
	TTL    time.Duration

	// Guardrails (#2200). MaxBoxes caps live UNCLAIMED anonymous boxes on
	// this daemon; the rate limits apply to creates only (a reconnect is
	// free), per key fingerprint and per source IP, as token buckets.
	// 0 = that limit is off.
	MaxBoxes        int
	PerKeyPerMinute float64
	PerKeyBurst     int
	PerIPPerMinute  float64
	PerIPBurst      int
}

// DefaultLimits is the owner's decision on #2204 (2026-10-01): 2 vCPU /
// 4 GB / 20 GB / 4 h; cap 20; per key 1 create per 10 min (burst 2); per
// source IP 6 per 10 min (burst 6).
func DefaultLimits() Limits {
	return Limits{
		CPU: "2", Memory: "4GB", Disk: "20GB", TTL: 4 * time.Hour,
		MaxBoxes: 20, PerKeyPerMinute: 0.1, PerKeyBurst: 2, PerIPPerMinute: 0.6, PerIPBurst: 6,
	}
}

// Rejections a caller can cause (#2200). The RPC layer maps them:
// DoorClosedError → FailedPrecondition with its message, ErrBanned →
// PermissionDenied, ErrRateLimited / ErrAtCapacity → ResourceExhausted.
var (
	ErrBanned      = errors.New("anonbox: this key is banned from the anonymous door")
	ErrRateLimited = errors.New("anonbox: slow down — too many new boxes from this key or address; try again in a few minutes")
	ErrAtCapacity  = errors.New("anonbox: we're full right now — sign up for a guaranteed box, or try again later")
)

// DoorClosedError carries the operator's message for a closed door.
type DoorClosedError struct{ Message string }

func (e DoorClosedError) Error() string {
	if e.Message == "" {
		return "anonbox: the anonymous door is closed"
	}
	return "anonbox: " + e.Message
}

// Config is everything the Manager needs beyond its two backends.
type Config struct {
	Limits Limits

	// NICDevice and Bridge name the instance-local NIC the egress ACL is
	// attached to (see incus.EnsureNICDevice for why it must be
	// instance-local). Typically "eth0" on the daemon's bridge.
	NICDevice string
	Bridge    string

	// ClaimSecret returns the per-box HMAC secret for claim tokens —
	// TokenManager.DeriveSharedSecret("anon-claim", boxName) in the daemon.
	// nil = no token is minted, no claim-url file is written, and Claim
	// refuses; the banner still shows the `containarium claim` hint.
	ClaimSecret func(boxName string) string
	// ClaimURLBase is prefixed to the token in the guest's claim-url file
	// as "<base>?token=<token>" (e.g. https://<cloud-domain>/claim). Empty
	// = the file holds the bare token (decision on #2199: the CLI prints
	// it with a note).
	ClaimURLBase string

	// DoorStatePath persists the kill switch and bans (#2200); "" keeps
	// them in memory only. A malformed file fails closed — see DoorStore.
	DoorStatePath string

	// Funnel records every step of a key's journey (#2201); nil = none.
	Funnel Funnel

	// Logf receives operational warnings (a wall that could not be
	// delivered, #2202); nil = the standard logger.
	Logf func(format string, args ...any)

	// Now is the clock; nil = time.Now.
	Now func() time.Time
}

// Boxes is the slice of box.BoxBackend (+ ExecCapable + TTLCapable) the
// Manager uses. The LXC backend satisfies it directly.
type Boxes interface {
	Create(ctx context.Context, spec box.BoxSpec) (*box.BoxStatus, error)
	Delete(ctx context.Context, ref box.BoxRef, force bool) error
	List(ctx context.Context) ([]box.BoxStatus, error)
	SetTTL(ctx context.Context, ref box.BoxRef, expiresAt *time.Time) error
	Exec(ctx context.Context, ref box.BoxRef, cmd []string) (stdout, stderr string, err error)
	WriteFile(ctx context.Context, ref box.BoxRef, path string, content []byte, mode string) error
	// Claim (#2199) — all addressed by boxRefFor(name), see Claim.
	SetMeta(ctx context.Context, ref box.BoxRef, meta map[string]string) error
	SetAuthorizedKeys(ctx context.Context, ref box.BoxRef, keys []string) error
	SetOwner(ctx context.Context, ref box.BoxRef, tenant string) error
}

// ACLs is the Incus network-ACL + NIC-device slice. incus.Backend
// satisfies it; the core-infra guard uses the same five calls.
type ACLs interface {
	GetNetworkACL(name string) (*api.NetworkACL, error)
	CreateNetworkACL(config incus.ACLConfig) error
	UpdateNetworkACL(name string, config incus.ACLConfig) error
	EnsureNICDevice(containerName string, want incus.NICDevice) error
	SetDeviceConfig(containerName, deviceName string, keys map[string]string) error
}

// InvalidRequestError marks a failure that is the caller's fault (a key
// that does not parse, a fingerprint that does not match it) so the RPC
// layer can answer InvalidArgument rather than Internal.
type InvalidRequestError struct{ Err error }

func (e InvalidRequestError) Error() string { return e.Err.Error() }
func (e InvalidRequestError) Unwrap() error { return e.Err }

// EnsureRequest is what the door knows about a connecting key.
type EnsureRequest struct {
	Fingerprint string // "SHA256:<base64>", as ssh.FingerprintSHA256; optional, verified against PublicKey when set
	PublicKey   string // one authorized_keys line
	SourceIP    string
}

// EnsureResult is the upstream the door should pipe the session to.
type EnsureResult struct {
	BoxName         string
	SSHHost         string
	SSHPort         int
	SSHUser         string
	TTLExpiresAt    time.Time
	Reused          bool // an existing live box for this key
	PreviousExpired bool // a box for this key existed earlier in this daemon's lifetime and is gone
}

// Manager resolves or creates the anonymous box for a key.
type Manager struct {
	boxes Boxes
	acls  ACLs
	cfg   Config

	// seen remembers fingerprints this process has created a box for, so a
	// reconnect after the sweeper reaped the box can be told apart from a
	// first visit. Best-effort by design: it does not survive a daemon
	// restart, and a wrong "false" only costs one banner line.
	mu    sync.Mutex
	seen  map[string]time.Time
	known map[string]knownBox // Observe's previous snapshot (#2201)

	// claimMu serializes Claim's compare-and-set on claimed_at: the box
	// backend has no atomic label update, so the daemon is the lock.
	claimMu sync.Mutex

	// Guardrails (#2200).
	door       *DoorStore
	keyLimiter *ratelimit.Limiter
	ipLimiter  *ratelimit.Limiter
}

// New returns a Manager over the given backends.
func New(boxes Boxes, acls ACLs, cfg Config) *Manager {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Limits == (Limits{}) {
		cfg.Limits = DefaultLimits()
	}
	if cfg.NICDevice == "" {
		cfg.NICDevice = "eth0"
	}
	return &Manager{
		boxes: boxes, acls: acls, cfg: cfg, seen: map[string]time.Time{},
		door:       NewDoorStore(cfg.DoorStatePath),
		keyLimiter: ratelimit.New(cfg.Limits.PerKeyPerMinute/60, cfg.Limits.PerKeyBurst),
		ipLimiter:  ratelimit.New(cfg.Limits.PerIPPerMinute/60, cfg.Limits.PerIPBurst),
	}
}

// DoorConfig is the door's current operator state.
func (m *Manager) DoorConfig() DoorConfig { return m.door.Get() }

// SetDoorConfig replaces and persists the door's operator state.
func (m *Manager) SetDoorConfig(cfg DoorConfig) error { return m.door.Set(cfg) }

// DoorErr reports a poisoned door state file (malformed on disk).
func (m *Manager) DoorErr() error { return m.door.Err() }

// Limits echoes the fixed limits.
func (m *Manager) Limits() Limits { return m.cfg.Limits }

// IsUnclaimedAnonymous reports whether labels describe an anonymous box
// nobody has claimed yet — the boxes that may not expose ports or routes.
func IsUnclaimedAnonymous(labels map[string]string) bool {
	return labels[LabelFingerprint] != "" && labels[LabelClaimedAt] == ""
}

// UsernameFor is the box's tenant/login name for a fingerprint: "anon-" +
// the first 8 hex of sha256(fingerprint). Stable, a valid Linux username,
// and not reversible to the key.
func UsernameFor(fingerprint string) string {
	return "anon-" + fpHash(fingerprint)[:8]
}

func fpHash(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:])
}

// Ensure returns the live box for the key, creating one when none exists.
// Every error path that created an instance deletes it again: the door
// never receives a half-provisioned upstream.
func (m *Manager) Ensure(ctx context.Context, req EnsureRequest) (*EnsureResult, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return nil, InvalidRequestError{Err: fmt.Errorf("anonbox: invalid public key: %w", err)}
	}
	fp := ssh.FingerprintSHA256(pub)
	if req.Fingerprint != "" && req.Fingerprint != fp {
		return nil, InvalidRequestError{Err: fmt.Errorf("anonbox: fingerprint %q does not match the presented key (%s)", req.Fingerprint, fp)}
	}
	username := UsernameFor(fp)
	hash := fpHash(fp)
	knock := m.cfg.Now()
	m.record(FunnelEvent{Kind: FunnelConnect, FPHash: hash})

	// Kill switch and bans come before everything, reconnects included:
	// a closed door is closed for the key that already has a box too.
	if door := m.door.Get(); !door.Enabled {
		err := DoorClosedError{Message: door.DisabledMessage}
		m.record(FunnelEvent{Kind: FunnelRejectedDoor, FPHash: hash, Reason: err.Error()})
		return nil, err
	}
	if m.door.IsBanned(fp) {
		m.record(FunnelEvent{Kind: FunnelRejectedDoor, FPHash: hash, Reason: ErrBanned.Error()})
		return nil, ErrBanned
	}

	if existing, err := m.findLive(ctx, fp); err != nil {
		return nil, err
	} else if existing != nil {
		// A claimed box reports its new tenant as Ref.Tenant; the login
		// is still the box's own user (decision on #2199), and its TTL is
		// gone.
		m.record(FunnelEvent{Kind: FunnelReconnect, FPHash: hash, BoxName: existing.Ref.Name})
		return &EnsureResult{
			BoxName:      existing.Ref.Name,
			SSHHost:      existing.IPAddress,
			SSHPort:      22,
			SSHUser:      boxRefFor(existing.Ref.Name).Tenant,
			TTLExpiresAt: existing.TTLExpiresAt,
			Reused:       true,
		}, nil
	}

	// Creates are what cost us; a reconnect above is free.
	if !m.keyLimiter.Allow(hash) || !m.ipLimiter.Allow(req.SourceIP) {
		m.record(FunnelEvent{Kind: FunnelRejectedRateLimit, FPHash: hash, Reason: ErrRateLimited.Error()})
		return nil, ErrRateLimited
	}
	if m.cfg.Limits.MaxBoxes > 0 {
		live, err := m.countUnclaimed(ctx)
		if err != nil {
			return nil, err
		}
		if live >= m.cfg.Limits.MaxBoxes {
			m.record(FunnelEvent{Kind: FunnelRejectedCapacity, FPHash: hash, Reason: ErrAtCapacity.Error()})
			return nil, ErrAtCapacity
		}
	}

	m.mu.Lock()
	_, previousExpired := m.seen[fp]
	m.mu.Unlock()

	now := m.cfg.Now()
	tokenID, err := newTokenID()
	if err != nil {
		return nil, err
	}
	spec := box.BoxSpec{
		Ref:       box.BoxRef{Tenant: username},
		OSType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		Isolation: pb.IsolationType_ISOLATION_TYPE_VM,
		Resources: box.ResourceLimits{CPU: m.cfg.Limits.CPU, Memory: m.cfg.Limits.Memory, Disk: m.cfg.Limits.Disk},
		SSHKeys:   []string{req.PublicKey},
		Labels: map[string]string{
			LabelFingerprint:  fp,
			LabelFPHash:       fpHash(fp),
			LabelCreatedAt:    now.UTC().Format(time.RFC3339),
			LabelSourceIP:     req.SourceIP,
			LabelClaimTokenID: tokenID,
			LabelPublicKey:    strings.TrimSpace(req.PublicKey),
		},
		AutoStart: true,
	}
	st, err := m.boxes.Create(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("anonbox: create %s: %w", username, err)
	}
	ref := st.Ref
	expiresAt := now.Add(m.cfg.Limits.TTL)

	if err := m.provision(ctx, ref, st, expiresAt, tokenID, previousExpired); err != nil {
		if derr := m.boxes.Delete(ctx, ref, true); derr != nil {
			err = errors.Join(err, fmt.Errorf("and cleanup of %s failed: %w", ref.Name, derr))
		}
		return nil, err
	}

	m.mu.Lock()
	m.seen[fp] = now
	if m.known != nil {
		m.known[ref.Name] = knownBox{fpHash: hash, expiresAt: expiresAt}
	}
	m.mu.Unlock()
	m.record(FunnelEvent{Kind: FunnelShellReady, FPHash: hash, BoxName: ref.Name, Duration: m.cfg.Now().Sub(knock)})

	return &EnsureResult{
		BoxName:         ref.Name,
		SSHHost:         st.IPAddress,
		SSHPort:         22,
		SSHUser:         ref.Tenant,
		TTLExpiresAt:    expiresAt,
		PreviousExpired: previousExpired,
	}, nil
}

// provision is everything after the instance exists: TTL, egress guard,
// in-guest files. Ordered so the guard is in place before anything the
// user can read lands.
func (m *Manager) provision(ctx context.Context, ref box.BoxRef, st *box.BoxStatus, expiresAt time.Time, tokenID string, previousExpired bool) error {
	if err := m.boxes.SetTTL(ctx, ref, &expiresAt); err != nil {
		return fmt.Errorf("anonbox: stamp ttl on %s: %w", ref.Name, err)
	}
	if err := m.applyEgressGuard(ref.Name); err != nil {
		return fmt.Errorf("anonbox: egress guard on %s: %w", ref.Name, err)
	}
	claimURL, err := m.claimURL(ref.Name, tokenID, expiresAt)
	if err != nil {
		return err
	}
	if err := m.writeGuestFiles(ctx, ref, guestFiles{
		expiresAt:       expiresAt,
		limits:          m.cfg.Limits,
		previousExpired: previousExpired,
		claimURL:        claimURL,
	}); err != nil {
		return fmt.Errorf("anonbox: guest files on %s: %w", ref.Name, err)
	}
	if claimURL != "" {
		m.record(FunnelEvent{Kind: FunnelClaimLinkIssued, FPHash: st.Labels[LabelFPHash], BoxName: ref.Name})
	}
	return nil
}

// claimURL mints the box's claim token (#2199) and renders what goes into
// the guest's claim-url file: "<base>?token=<token>", or the bare token
// when no base is configured. "" when claims are not enabled.
func (m *Manager) claimURL(boxName, tokenID string, expiresAt time.Time) (string, error) {
	if m.cfg.ClaimSecret == nil {
		return "", nil
	}
	fp := ""
	if st, err := m.findByName(context.Background(), boxName); err == nil && st != nil {
		fp = st.Labels[LabelFPHash]
	}
	token, err := MintClaimToken(m.cfg.ClaimSecret(boxName), ClaimToken{BoxName: boxName, FPHash: fp, ExpiresAt: expiresAt, TokenID: tokenID})
	if err != nil {
		return "", fmt.Errorf("anonbox: mint claim token for %s: %w", boxName, err)
	}
	if m.cfg.ClaimURLBase == "" {
		return token, nil
	}
	return strings.TrimRight(m.cfg.ClaimURLBase, "/") + "?token=" + token, nil
}

// countUnclaimed is the global-cap denominator: anonymous boxes nobody
// has claimed. A claimed box belongs to a tenant and no longer counts.
func (m *Manager) countUnclaimed(ctx context.Context) (int, error) {
	all, err := m.boxes.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("anonbox: list boxes: %w", err)
	}
	n := 0
	for i := range all {
		if IsUnclaimedAnonymous(all[i].Labels) {
			n++
		}
	}
	return n, nil
}

// findLive returns the box labelled with fp, or nil.
func (m *Manager) findLive(ctx context.Context, fp string) (*box.BoxStatus, error) {
	all, err := m.boxes.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("anonbox: list boxes: %w", err)
	}
	for i := range all {
		if all[i].Labels[LabelFingerprint] == fp {
			return &all[i], nil
		}
	}
	return nil, nil
}

func newTokenID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("anonbox: token id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
