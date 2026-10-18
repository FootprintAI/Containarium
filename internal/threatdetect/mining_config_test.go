package threatdetect

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestDefaultMiningThresholds(t *testing.T) {
	d := DefaultMiningThresholds()
	if d.MinCores != 1.5 || d.MinFractionOfLimit != 0.75 || d.Window != 5*time.Minute || d.FlowMinAge != 3*time.Minute {
		t.Fatalf("defaults = %+v", d)
	}
	if !slices.Equal(d.StratumPorts, []uint32{3333, 4444, 5555, 7777, 14444, 14433}) {
		t.Fatalf("default stratum ports = %v", d.StratumPorts)
	}
}

func TestMiningThresholdsFromProto_ZeroFieldsFallBackToDefaults(t *testing.T) {
	got := MiningThresholdsFromProto(&pb.MiningBehaviorThresholds{MinCores: 4, Window: durationpb.New(10 * time.Minute)})
	if got.MinCores != 4 || got.Window != 10*time.Minute {
		t.Fatalf("set fields not honoured: %+v", got)
	}
	d := DefaultMiningThresholds()
	if got.MinFractionOfLimit != d.MinFractionOfLimit || got.FlowMinAge != d.FlowMinAge || !slices.Equal(got.StratumPorts, d.StratumPorts) {
		t.Fatalf("unset fields did not default: %+v", got)
	}
	if nilGot := MiningThresholdsFromProto(nil); nilGot.MinCores != d.MinCores {
		t.Fatalf("nil proto = %+v, want defaults", nilGot)
	}
}

func TestMiningThresholds_Bar(t *testing.T) {
	d := DefaultMiningThresholds()
	cases := []struct {
		limit, want float64
	}{
		{0, 1.5},  // no limit: min_cores alone
		{1, 0.75}, // 1 vCPU: 0.75 x 1
		{2, 1.5},  // tie
		{8, 1.5},  // 8 vCPU: min_cores is lower
		{0.25, 0.1875},
	}
	for _, c := range cases {
		if got := d.Bar(c.limit); got != c.want {
			t.Errorf("Bar(%v) = %v, want %v", c.limit, got, c.want)
		}
	}
}

func TestMiningThresholdsConfig_SetValidatesAndServesEffective(t *testing.T) {
	c, err := NewMiningThresholdsConfig(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Effective(); got.MinCores != 1.5 {
		t.Fatalf("fresh Effective = %+v, want defaults", got)
	}
	bad := []*pb.MiningBehaviorThresholds{
		{MinCores: -1},
		{MinFractionOfLimit: -0.1},
		{Window: durationpb.New(-time.Second)},
		{FlowMinAge: durationpb.New(-time.Second)},
		{StratumPorts: []uint32{0}},
		{StratumPorts: []uint32{70000}},
	}
	for _, b := range bad {
		if err := c.Set(context.Background(), b); err == nil {
			t.Errorf("Set(%v) = nil error, want rejection", b)
		}
	}
	if err := c.Set(context.Background(), &pb.MiningBehaviorThresholds{MinCores: 2, StratumPorts: []uint32{3333}}); err != nil {
		t.Fatal(err)
	}
	got := c.Effective()
	if got.MinCores != 2 || !slices.Equal(got.StratumPorts, []uint32{3333}) || got.Window != 5*time.Minute {
		t.Fatalf("Effective after Set = %+v", got)
	}
	if stored := c.Get(); stored.GetMinCores() != 2 {
		t.Fatalf("Get = %v", stored)
	}
}

func TestMiningThresholdsConfigKey(t *testing.T) {
	if MiningThresholdsConfigKey != "threatdetect.mining_behavior.thresholds" {
		t.Fatalf("config key = %q", MiningThresholdsConfigKey)
	}
}

// memKV is an in-memory ConfigKV standing in for app.DaemonConfigStore.
type memKV map[string]string

func (m memKV) Get(_ context.Context, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", app.ErrDaemonConfigNotFound
	}
	return v, nil
}

func (m memKV) Set(_ context.Context, key, value string) error {
	m[key] = value
	return nil
}

// AC2: thresholds persist in the config store as protojson and survive a
// restart (a fresh config over the same store).
func TestMiningThresholdsConfig_PersistsAcrossRestart(t *testing.T) {
	kv := memKV{}
	c, err := NewMiningThresholdsConfig(context.Background(), kv)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Set(context.Background(), &pb.MiningBehaviorThresholds{MinCores: 3, FlowMinAge: durationpb.New(time.Minute), StratumPorts: []uint32{3333, 9999}}); err != nil {
		t.Fatal(err)
	}
	raw, ok := kv[MiningThresholdsConfigKey]
	if !ok {
		t.Fatalf("nothing stored under %q", MiningThresholdsConfigKey)
	}
	var decoded pb.MiningBehaviorThresholds
	if err := protojson.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("stored value is not protojson: %v (%q)", err, raw)
	}
	reloaded, err := NewMiningThresholdsConfig(context.Background(), kv)
	if err != nil {
		t.Fatal(err)
	}
	got := reloaded.Effective()
	if got.MinCores != 3 || got.FlowMinAge != time.Minute || !slices.Equal(got.StratumPorts, []uint32{3333, 9999}) {
		t.Fatalf("reloaded Effective = %+v", got)
	}
}

// A window shorter than flow_min_age (explicit or defaulted) is rejected.
func TestMiningThresholdsConfig_RejectsWindowShorterThanFlowMinAge(t *testing.T) {
	c, err := NewMiningThresholdsConfig(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*pb.MiningBehaviorThresholds{
		{Window: durationpb.New(2 * time.Minute), FlowMinAge: durationpb.New(3 * time.Minute)},
		{Window: durationpb.New(2 * time.Minute)},      // default flow_min_age 3m
		{FlowMinAge: durationpb.New(10 * time.Minute)}, // default window 5m
	} {
		if err := c.Set(context.Background(), m); err == nil {
			t.Errorf("Set(%v) = nil error, want rejection", m)
		}
	}
	if err := c.Set(context.Background(), &pb.MiningBehaviorThresholds{Window: durationpb.New(3 * time.Minute), FlowMinAge: durationpb.New(3 * time.Minute)}); err != nil {
		t.Errorf("window == flow_min_age rejected: %v", err)
	}
}

// A window shorter than MinMiningWindow can never be satisfied either: the
// sweep keeps samples newer than now-window, so at the 30 s tick the oldest
// retained sample is at most window-30 s old, below the 0.8 x window
// coverage the rule demands once 0.2 x window < 30 s (window < 150 s). The
// threshold is accepted by the CLI otherwise and the rule silently never
// fires (#2674).
func TestMiningThresholdsConfig_RejectsWindowBelowMin(t *testing.T) {
	c, err := NewMiningThresholdsConfig(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Set(context.Background(), &pb.MiningBehaviorThresholds{Window: durationpb.New(MinMiningWindow), FlowMinAge: durationpb.New(MinMiningWindow)}); err != nil {
		t.Errorf("window == MinMiningWindow rejected: %v", err)
	}
	for _, w := range []time.Duration{2 * time.Minute, 149 * time.Second, MinMiningWindow - time.Second} {
		err := c.Set(context.Background(), &pb.MiningBehaviorThresholds{Window: durationpb.New(w), FlowMinAge: durationpb.New(30 * time.Second)})
		if err == nil || !strings.Contains(err.Error(), "below the minimum") || !strings.Contains(err.Error(), MinMiningWindow.String()) {
			t.Errorf("window %s: err = %v, want rejection naming the minimum %s", w, err, MinMiningWindow)
		}
	}
}

// Every accepted window must actually fire on the production cadence: a box
// at 2 cores of a 2-core limit with a chatty :3333 flow, one CPU sample per
// 30 s tick and a sweep after each tick, for every whole-minute window from
// the minimum to the maximum (#2674). The shared 15 s harness above has
// twice the headroom and cannot see a window the real cadence starves.
func TestMiningBehaviorRule_FiresForEveryAcceptedWindow(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.5")
	for w := MinMiningWindow; w <= MaxMiningWindow; w += time.Minute {
		th := DefaultMiningThresholds()
		th.Window = w
		th.FlowMinAge = 30 * time.Second
		now := time.Unix(1_760_140_800, 0)
		ctx := func() RuleContext {
			return RuleContext{
				TenantForIP:      fakeTenants(map[string]string{"10.0.0.5": "alice"}),
				Now:              func() time.Time { return now },
				MiningThresholds: func() MiningThresholds { return th },
			}
		}
		r := NewMiningBehaviorRule(nil)
		start, fired := now, false
		for ; now.Sub(start) <= 2*w+time.Minute && !fired; now = now.Add(30 * time.Second) {
			r.OnCPU(ctx(), []CPUSample{{Container: "box", IP: ip, Cores: 2, LimitCores: 2, At: now}})
			age := uint64(now.Sub(start).Nanoseconds()) // #nosec G115 -- non-negative
			r.OnFlows(ctx(), []netbpf.FlowRecord{{
				Saddr: beIP(10, 0, 0, 5), Daddr: beIP(203, 0, 113, 9), Sport: 40000, Dport: 3333, Proto: 6,
				Bytes: 4096, Packets: 32, FirstNs: 1_000, LastNs: 1_000 + age,
			}})
			fired = len(r.Sweep(ctx(), now)) > 0
		}
		if !fired {
			t.Errorf("window %s was accepted by validation but never fired over %s of 30 s samples", w, 2*w+time.Minute)
		}
	}
}

// A window above MaxMiningWindow can never be satisfied (the sample cap
// cannot span it) and is rejected rather than silently never firing.
func TestMiningThresholdsConfig_RejectsWindowAboveMax(t *testing.T) {
	c, err := NewMiningThresholdsConfig(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Set(context.Background(), &pb.MiningBehaviorThresholds{Window: durationpb.New(MaxMiningWindow)}); err != nil {
		t.Errorf("window == MaxMiningWindow rejected: %v", err)
	}
	err = c.Set(context.Background(), &pb.MiningBehaviorThresholds{Window: durationpb.New(MaxMiningWindow + time.Minute)})
	if err == nil || !strings.Contains(err.Error(), "exceeds the maximum") || !strings.Contains(err.Error(), MaxMiningWindow.String()) {
		t.Errorf("window > MaxMiningWindow: err = %v, want rejection naming the limit", err)
	}
}
