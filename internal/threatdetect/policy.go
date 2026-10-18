package threatdetect

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/internal/app"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ProcessPolicy (#2636) says what a HIGH mining finding does to its
// container. The pure parts live here — resolution, validation, and the
// DaemonConfigStore-backed store; the responder that acts on it is
// internal/server/process_responder.go. See
// docs/architecture/process-exec-guardrail.md, component 7.

const (
	// ProcessPolicyKey is the DaemonConfigStore key of the backend default,
	// stored as protojson.
	ProcessPolicyKey = "threatdetect.process_policy"
	// processPolicyContainerKeyPrefix prefixes one container's override key.
	processPolicyContainerKeyPrefix = "threatdetect.process_policy.container."

	// DefaultThrottleAllowance is the limits.cpu.allowance THROTTLE applies
	// when no level sets one.
	DefaultThrottleAllowance = "10%"
	// DefaultProcessActionTTL is how long an applied action stays in effect
	// with no operator decision — the same 24h backstop auto_quarantine.go
	// uses.
	DefaultProcessActionTTL = 24 * time.Hour
	// minProcessActionTTL rejects a TTL so short the operator could never
	// reach the box before the backstop undid the action.
	minProcessActionTTL = time.Minute
)

// ProcessPolicyContainerKey is the DaemonConfigStore key of container's
// override.
func ProcessPolicyContainerKey(container string) string {
	return processPolicyContainerKeyPrefix + container
}

// BuiltinProcessPolicy is the policy in effect when nothing is stored:
// ALERT. Nothing acts until an operator sets otherwise.
func BuiltinProcessPolicy() *pb.ProcessPolicy {
	return &pb.ProcessPolicy{
		Action:            pb.ProcessAction_PROCESS_ACTION_ALERT,
		ThrottleAllowance: DefaultThrottleAllowance,
		Ttl:               durationpb.New(DefaultProcessActionTTL),
	}
}

// ResolveProcessPolicy merges container override → backend default →
// built-in, field by field: an empty field at one level inherits the next.
// Either argument may be nil (nothing stored at that level).
func ResolveProcessPolicy(override, backend *pb.ProcessPolicy) *pb.ProcessPolicy {
	out := BuiltinProcessPolicy()
	for _, level := range []*pb.ProcessPolicy{backend, override} {
		if level == nil {
			continue
		}
		if level.GetAction() != pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED {
			out.Action = level.GetAction()
		}
		if level.GetThrottleAllowance() != "" {
			out.ThrottleAllowance = level.GetThrottleAllowance()
		}
		if d := level.GetTtl().AsDuration(); level.GetTtl() != nil && d > 0 {
			out.Ttl = durationpb.New(d)
		}
	}
	return out
}

var (
	allowancePercentRe = regexp.MustCompile(`^([0-9]{1,3})%$`)
	allowanceQuotaRe   = regexp.MustCompile(`^([0-9]{1,9})ms/([0-9]{1,9})ms$`)
)

// ValidateThrottleAllowance accepts the two Incus limits.cpu.allowance
// shapes: "N%" (1–100, a share under contention) and "Nms/Mms" (a hard CFS
// quota, both positive).
func ValidateThrottleAllowance(s string) error {
	if m := allowancePercentRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n < 1 || n > 100 {
			return fmt.Errorf("throttle_allowance %q: percent must be between 1%% and 100%%", s)
		}
		return nil
	}
	if m := allowanceQuotaRe.FindStringSubmatch(s); m != nil {
		q, _ := strconv.Atoi(m[1])
		p, _ := strconv.Atoi(m[2])
		if q < 1 || p < 1 {
			return fmt.Errorf("throttle_allowance %q: quota and period must be positive", s)
		}
		return nil
	}
	return fmt.Errorf("throttle_allowance %q: want \"N%%\" or \"Nms/Mms\"", s)
}

// ValidateProcessPolicy rejects a policy no level could apply. Empty fields
// are valid (they inherit); only set fields are checked.
func ValidateProcessPolicy(p *pb.ProcessPolicy) error {
	if p == nil {
		return errors.New("policy is required")
	}
	if _, known := pb.ProcessAction_name[int32(p.GetAction())]; !known {
		return fmt.Errorf("action %d is not a known ProcessAction", int32(p.GetAction()))
	}
	if a := p.GetThrottleAllowance(); a != "" {
		if err := ValidateThrottleAllowance(a); err != nil {
			return err
		}
	}
	if p.GetTtl() != nil {
		d := p.GetTtl().AsDuration()
		if d < 0 {
			return fmt.Errorf("ttl %v must not be negative", d)
		}
		if d > 0 && d < minProcessActionTTL {
			return fmt.Errorf("ttl %v must be at least %v", d, minProcessActionTTL)
		}
	}
	return nil
}

// RespondsTo reports whether a HIGH finding from rule is one the process
// responder acts on: the two mining rules. The values are numeric until
// #2635 (MINING_BEHAVIOR = 6) and #2638 (MINER_SIGNATURE = 7) land their
// enum names in the proto; swap to the named constants then.
func RespondsTo(rule pb.ThreatRuleId) bool {
	const (
		ruleMiningBehavior pb.ThreatRuleId = 6
		ruleMinerSignature pb.ThreatRuleId = 7
	)
	return rule == ruleMiningBehavior || rule == ruleMinerSignature
}

// PolicyConfigStore is the slice of *app.DaemonConfigStore the policy store
// needs: Get returns an error wrapping app.ErrDaemonConfigNotFound for a
// missing key, exactly as DaemonConfigStore.Get does.
type PolicyConfigStore interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// ProcessPolicyStore persists the backend default and per-container
// overrides as protojson in DaemonConfigStore. With a nil config store (no
// Postgres) policies live in memory for the process lifetime — the same
// fallback BadDestinationRule uses for operator entries. An empty stored
// value means "unset": DaemonConfigStore has no delete, so ClearOverride
// writes "".
type ProcessPolicyStore struct {
	cfg PolicyConfigStore

	mu  sync.Mutex
	mem map[string]string // used only when cfg == nil
}

// NewProcessPolicyStore builds a store over cfg; nil cfg is in-memory only.
func NewProcessPolicyStore(cfg PolicyConfigStore) *ProcessPolicyStore {
	return &ProcessPolicyStore{cfg: cfg, mem: make(map[string]string)}
}

// Default returns the stored backend default, or nil when none is stored.
func (s *ProcessPolicyStore) Default(ctx context.Context) (*pb.ProcessPolicy, error) {
	return s.get(ctx, ProcessPolicyKey)
}

// Override returns container's stored override, or nil when none is stored.
func (s *ProcessPolicyStore) Override(ctx context.Context, container string) (*pb.ProcessPolicy, error) {
	if container == "" {
		return nil, nil
	}
	return s.get(ctx, ProcessPolicyContainerKey(container))
}

// SetDefault stores the backend default.
func (s *ProcessPolicyStore) SetDefault(ctx context.Context, p *pb.ProcessPolicy) error {
	return s.set(ctx, ProcessPolicyKey, p)
}

// SetOverride stores container's override.
func (s *ProcessPolicyStore) SetOverride(ctx context.Context, container string, p *pb.ProcessPolicy) error {
	if container == "" {
		return errors.New("container is required for an override")
	}
	return s.set(ctx, ProcessPolicyContainerKey(container), p)
}

// ClearOverride removes container's override so it inherits the backend
// default again.
func (s *ProcessPolicyStore) ClearOverride(ctx context.Context, container string) error {
	if container == "" {
		return errors.New("container is required for an override")
	}
	return s.setRaw(ctx, ProcessPolicyContainerKey(container), "")
}

// Effective resolves the policy the responder applies to container
// (override → default → built-in). An empty container resolves the backend
// level. A store failure is an error, never a silent fall-through to the
// built-in: the responder must not act on ALERT believing nothing stronger
// was configured.
func (s *ProcessPolicyStore) Effective(ctx context.Context, container string) (*pb.ProcessPolicy, error) {
	backend, err := s.Default(ctx)
	if err != nil {
		return nil, err
	}
	override, err := s.Override(ctx, container)
	if err != nil {
		return nil, err
	}
	return ResolveProcessPolicy(override, backend), nil
}

func (s *ProcessPolicyStore) get(ctx context.Context, key string) (*pb.ProcessPolicy, error) {
	var raw string
	if s.cfg == nil {
		s.mu.Lock()
		raw = s.mem[key]
		s.mu.Unlock()
	} else {
		v, err := s.cfg.Get(ctx, key)
		if err != nil {
			if errors.Is(err, app.ErrDaemonConfigNotFound) {
				return nil, nil
			}
			return nil, fmt.Errorf("threatdetect: read process policy %q: %w", key, err)
		}
		raw = v
	}
	if raw == "" {
		return nil, nil
	}
	var p pb.ProcessPolicy
	if err := protojson.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("threatdetect: process policy %q is not valid protojson: %w", key, err)
	}
	return &p, nil
}

func (s *ProcessPolicyStore) set(ctx context.Context, key string, p *pb.ProcessPolicy) error {
	if err := ValidateProcessPolicy(p); err != nil {
		return err
	}
	raw, err := protojson.Marshal(p)
	if err != nil {
		return fmt.Errorf("threatdetect: marshal process policy: %w", err)
	}
	return s.setRaw(ctx, key, string(raw))
}

func (s *ProcessPolicyStore) setRaw(ctx context.Context, key, raw string) error {
	if s.cfg == nil {
		s.mu.Lock()
		s.mem[key] = raw
		s.mu.Unlock()
		return nil
	}
	if err := s.cfg.Set(ctx, key, raw); err != nil {
		return fmt.Errorf("threatdetect: persist process policy %q: %w", key, err)
	}
	return nil
}
