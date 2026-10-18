package threatdetect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/app"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// MiningThresholdsConfigKey is the DaemonConfigStore key the operator's
// mining-behavior thresholds are persisted under, as protojson of
// pb.MiningBehaviorThresholds (#2635). #2636's ProcessPolicy wraps the same
// message.
const MiningThresholdsConfigKey = "threatdetect.mining_behavior.thresholds"

// Mining-behavior defaults (PRD story 2, decided on #2641 Q1).
const (
	DefaultMiningMinCores           = 1.5
	DefaultMiningMinFractionOfLimit = 0.75
	DefaultMiningWindow             = 5 * time.Minute
	DefaultMiningFlowMinAge         = 3 * time.Minute
)

// DefaultMiningStratumPorts are the destination ports treated as stratum
// (mining pool) ports when the operator has not set a list.
var DefaultMiningStratumPorts = []uint32{3333, 4444, 5555, 7777, 14444, 14433}

// MiningThresholds is the resolved (defaults applied) form of
// pb.MiningBehaviorThresholds the mining-behavior rule evaluates against.
type MiningThresholds struct {
	MinCores           float64
	MinFractionOfLimit float64
	Window             time.Duration
	FlowMinAge         time.Duration
	StratumPorts       []uint32
}

// DefaultMiningThresholds returns the shipped defaults.
func DefaultMiningThresholds() MiningThresholds {
	return MiningThresholds{
		MinCores:           DefaultMiningMinCores,
		MinFractionOfLimit: DefaultMiningMinFractionOfLimit,
		Window:             DefaultMiningWindow,
		FlowMinAge:         DefaultMiningFlowMinAge,
		StratumPorts:       slices.Clone(DefaultMiningStratumPorts),
	}
}

// MiningThresholdsFromProto resolves a stored message: every zero or empty
// field falls back to its default, so a partial message tunes only what it
// sets. nil yields the defaults.
func MiningThresholdsFromProto(m *pb.MiningBehaviorThresholds) MiningThresholds {
	t := DefaultMiningThresholds()
	if v := m.GetMinCores(); v > 0 {
		t.MinCores = v
	}
	if v := m.GetMinFractionOfLimit(); v > 0 {
		t.MinFractionOfLimit = v
	}
	if d := m.GetWindow().AsDuration(); m.GetWindow() != nil && d > 0 {
		t.Window = d
	}
	if d := m.GetFlowMinAge().AsDuration(); m.GetFlowMinAge() != nil && d > 0 {
		t.FlowMinAge = d
	}
	if ports := m.GetStratumPorts(); len(ports) > 0 {
		t.StratumPorts = slices.Clone(ports)
	}
	return t
}

// Bar is the mean-cores level a box must reach: min(MinCores,
// MinFractionOfLimit x limitCores), or MinCores alone when the box has no
// CPU limit (limitCores <= 0).
func (t MiningThresholds) Bar(limitCores float64) float64 {
	if limitCores <= 0 {
		return t.MinCores
	}
	return min(t.MinCores, t.MinFractionOfLimit*limitCores)
}

func (t MiningThresholds) isStratumPort(port uint16) bool {
	return slices.Contains(t.StratumPorts, uint32(port))
}

// ConfigKV is the slice of app.DaemonConfigStore the thresholds config uses.
type ConfigKV interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// MiningThresholdsConfig holds the operator's mining-behavior thresholds,
// cached in memory and persisted to the daemon config store. Effective is
// what the engine's RuleContext reads on every sweep, so it never touches
// the store.
type MiningThresholdsConfig struct {
	store ConfigKV // nil = in-memory only for this process's lifetime

	mu  sync.RWMutex
	cur *pb.MiningBehaviorThresholds
}

// NewMiningThresholdsConfig loads previously persisted thresholds from store
// (nil: in-memory only, like the bad-destination list without Postgres).
func NewMiningThresholdsConfig(ctx context.Context, store ConfigKV) (*MiningThresholdsConfig, error) {
	c := &MiningThresholdsConfig{store: store, cur: &pb.MiningBehaviorThresholds{}}
	if store == nil {
		return c, nil
	}
	raw, err := store.Get(ctx, MiningThresholdsConfigKey)
	if err != nil {
		if errors.Is(err, app.ErrDaemonConfigNotFound) {
			return c, nil
		}
		return nil, fmt.Errorf("threatdetect: load mining-behavior thresholds: %w", err)
	}
	stored := &pb.MiningBehaviorThresholds{}
	if err := protojson.Unmarshal([]byte(raw), stored); err != nil {
		return nil, fmt.Errorf("threatdetect: decode mining-behavior thresholds: %w", err)
	}
	c.cur = stored
	return c, nil
}

// Get returns a copy of the stored (unresolved) thresholds message.
func (c *MiningThresholdsConfig) Get() *pb.MiningBehaviorThresholds {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return proto.Clone(c.cur).(*pb.MiningBehaviorThresholds)
}

// Set validates, persists and applies new thresholds; the next sweep uses
// them. It is the Go entry point #2636's `process-policy set` will call.
func (c *MiningThresholdsConfig) Set(ctx context.Context, m *pb.MiningBehaviorThresholds) error {
	if err := validateMiningThresholds(m); err != nil {
		return err
	}
	next := proto.Clone(m).(*pb.MiningBehaviorThresholds)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.store != nil {
		raw, err := protojson.Marshal(next)
		if err != nil {
			return fmt.Errorf("threatdetect: encode mining-behavior thresholds: %w", err)
		}
		if err := c.store.Set(ctx, MiningThresholdsConfigKey, string(raw)); err != nil {
			return fmt.Errorf("threatdetect: persist mining-behavior thresholds: %w", err)
		}
	}
	c.cur = next
	return nil
}

// Effective returns the stored thresholds with defaults applied.
func (c *MiningThresholdsConfig) Effective() MiningThresholds {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return MiningThresholdsFromProto(c.cur)
}

func validateMiningThresholds(m *pb.MiningBehaviorThresholds) error {
	switch {
	case m == nil:
		return errors.New("threatdetect: mining-behavior thresholds: nil")
	case m.GetMinCores() < 0:
		return errors.New("threatdetect: mining-behavior thresholds: min_cores must be >= 0")
	case m.GetMinFractionOfLimit() < 0:
		return errors.New("threatdetect: mining-behavior thresholds: min_fraction_of_limit must be >= 0")
	case m.GetWindow() != nil && m.GetWindow().AsDuration() < 0:
		return errors.New("threatdetect: mining-behavior thresholds: window must be >= 0")
	case m.GetFlowMinAge() != nil && m.GetFlowMinAge().AsDuration() < 0:
		return errors.New("threatdetect: mining-behavior thresholds: flow_min_age must be >= 0")
	}
	for _, p := range m.GetStratumPorts() {
		if p == 0 || p > 65535 {
			return fmt.Errorf("threatdetect: mining-behavior thresholds: stratum port %d out of range 1-65535", p)
		}
	}
	// Checked on the resolved values, so a window set below the default
	// flow_min_age (or the reverse) is caught too.
	if eff := MiningThresholdsFromProto(m); eff.Window < eff.FlowMinAge {
		return fmt.Errorf("threatdetect: mining-behavior thresholds: window %s is shorter than flow_min_age %s", eff.Window, eff.FlowMinAge)
	} else if eff.Window > MaxMiningWindow {
		return fmt.Errorf("threatdetect: mining-behavior thresholds: window %s exceeds the maximum %s (the per-container sample cap cannot cover a longer window)", eff.Window, MaxMiningWindow)
	}
	return nil
}
