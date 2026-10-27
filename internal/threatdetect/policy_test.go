package threatdetect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/internal/app"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeConfigStore stands in for *app.DaemonConfigStore: the same Get/Set
// contract, including the ErrDaemonConfigNotFound sentinel for a missing
// key (see daemon_config_store.go — absence is an error, not "").
type fakeConfigStore struct {
	values map[string]string
	err    error
}

func (f *fakeConfigStore) Get(_ context.Context, key string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.values[key]
	if !ok {
		return "", app.ErrDaemonConfigNotFound
	}
	return v, nil
}

func (f *fakeConfigStore) Set(_ context.Context, key, value string) error {
	if f.err != nil {
		return f.err
	}
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[key] = value
	return nil
}

func policy(action pb.ProcessAction, allowance string, ttl time.Duration) *pb.ProcessPolicy {
	p := &pb.ProcessPolicy{Action: action, ThrottleAllowance: allowance}
	if ttl != 0 {
		p.Ttl = durationpb.New(ttl)
	}
	return p
}

// effective is policy() as ResolveProcessPolicy returns it: a resolved
// policy always carries kill_process, false unless a level set it (#2638).
func effective(action pb.ProcessAction, allowance string, ttl time.Duration) *pb.ProcessPolicy {
	p := policy(action, allowance, ttl)
	p.KillProcess = proto.Bool(false)
	return p
}

// The effective-policy resolution table from the design doc: container
// override → backend default → built-in {ALERT, "10%", 24h}, field by field
// so a partial override inherits what it leaves empty.
func TestResolveProcessPolicy(t *testing.T) {
	tests := []struct {
		name              string
		override, backend *pb.ProcessPolicy
		want              *pb.ProcessPolicy
	}{
		{
			name: "nothing stored is the built-in ALERT",
			want: effective(pb.ProcessAction_PROCESS_ACTION_ALERT, "10%", 24*time.Hour),
		},
		{
			name:    "backend default applies when no override",
			backend: policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "5%", 2*time.Hour),
			want:    effective(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "5%", 2*time.Hour),
		},
		{
			name:     "override wins over backend default",
			override: policy(pb.ProcessAction_PROCESS_ACTION_FREEZE, "", 0),
			backend:  policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "5%", 2*time.Hour),
			want:     effective(pb.ProcessAction_PROCESS_ACTION_FREEZE, "5%", 2*time.Hour),
		},
		{
			name:    "partial backend default inherits built-in fields",
			backend: policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "", 0),
			want:    effective(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 24*time.Hour),
		},
		{
			name:     "override can set ALERT explicitly over a THROTTLE default",
			override: policy(pb.ProcessAction_PROCESS_ACTION_ALERT, "", 0),
			backend:  policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "", 0),
			want:     effective(pb.ProcessAction_PROCESS_ACTION_ALERT, "10%", 24*time.Hour),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveProcessPolicy(tt.override, tt.backend)
			if !proto.Equal(got, tt.want) {
				t.Fatalf("ResolveProcessPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateProcessPolicy(t *testing.T) {
	tests := []struct {
		name    string
		p       *pb.ProcessPolicy
		wantErr string
	}{
		{name: "nil is an error", p: nil, wantErr: "policy is required"},
		{name: "empty inherits everything", p: &pb.ProcessPolicy{}},
		{name: "throttle with share allowance", p: policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)},
		{name: "throttle with hard quota", p: policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10ms/100ms", 0)},
		{name: "unknown action", p: &pb.ProcessPolicy{Action: pb.ProcessAction(42)}, wantErr: "action"},
		{name: "allowance without unit", p: policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10", 0), wantErr: "throttle_allowance"},
		{name: "allowance over 100%", p: policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "150%", 0), wantErr: "throttle_allowance"},
		{name: "allowance zero", p: policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "0%", 0), wantErr: "throttle_allowance"},
		{name: "negative ttl", p: policy(pb.ProcessAction_PROCESS_ACTION_ALERT, "", -time.Minute), wantErr: "ttl"},
		{name: "ttl under a minute", p: policy(pb.ProcessAction_PROCESS_ACTION_ALERT, "", 30*time.Second), wantErr: "ttl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProcessPolicy(tt.p)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateProcessPolicy() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateProcessPolicy() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// The store persists protojson under the two documented DaemonConfigStore
// keys, treats an empty value as "unset" (that is how ClearOverride works —
// DaemonConfigStore has no delete), and resolves Effective per container.
func TestProcessPolicyStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	cfg := &fakeConfigStore{}
	s := NewProcessPolicyStore(cfg)

	if got, err := s.Default(ctx); err != nil || got != nil {
		t.Fatalf("Default() on empty store = %v, %v; want nil, nil", got, err)
	}
	eff, err := s.Effective(ctx, "box-a")
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if !proto.Equal(eff, BuiltinProcessPolicy()) {
		t.Fatalf("Effective() on empty store = %v, want built-in", eff)
	}

	def := policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "5%", time.Hour)
	if err := s.SetDefault(ctx, def); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	raw, ok := cfg.values[ProcessPolicyKey]
	if !ok {
		t.Fatalf("SetDefault did not persist under %q; keys: %v", ProcessPolicyKey, cfg.values)
	}
	var persisted pb.ProcessPolicy
	if err := protojson.Unmarshal([]byte(raw), &persisted); err != nil {
		t.Fatalf("persisted value is not protojson: %v (%q)", err, raw)
	}
	if !proto.Equal(&persisted, def) {
		t.Fatalf("persisted = %v, want %v", &persisted, def)
	}

	ov := policy(pb.ProcessAction_PROCESS_ACTION_FREEZE, "", 0)
	if err := s.SetOverride(ctx, "box-a", ov); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	if _, ok := cfg.values[ProcessPolicyContainerKey("box-a")]; !ok {
		t.Fatalf("SetOverride did not persist under %q", ProcessPolicyContainerKey("box-a"))
	}
	got, err := s.Override(ctx, "box-a")
	if err != nil || !proto.Equal(got, ov) {
		t.Fatalf("Override(box-a) = %v, %v; want %v", got, err, ov)
	}
	if got, err := s.Override(ctx, "box-b"); err != nil || got != nil {
		t.Fatalf("Override(box-b) = %v, %v; want nil, nil", got, err)
	}

	eff, err = s.Effective(ctx, "box-a")
	if err != nil {
		t.Fatalf("Effective(box-a): %v", err)
	}
	want := effective(pb.ProcessAction_PROCESS_ACTION_FREEZE, "5%", time.Hour)
	if !proto.Equal(eff, want) {
		t.Fatalf("Effective(box-a) = %v, want %v", eff, want)
	}
	eff, err = s.Effective(ctx, "box-b")
	if err != nil || !proto.Equal(eff, effective(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "5%", time.Hour)) {
		t.Fatalf("Effective(box-b) = %v, %v; want backend default %v", eff, err, def)
	}

	if err := s.ClearOverride(ctx, "box-a"); err != nil {
		t.Fatalf("ClearOverride: %v", err)
	}
	if got, err := s.Override(ctx, "box-a"); err != nil || got != nil {
		t.Fatalf("Override after clear = %v, %v; want nil, nil", got, err)
	}
	eff, _ = s.Effective(ctx, "box-a")
	if !proto.Equal(eff, effective(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "5%", time.Hour)) {
		t.Fatalf("Effective after clear = %v, want backend default %v", eff, def)
	}
}

// A nil config store (no Postgres) keeps policies for the process lifetime
// — same fallback BadDestinationRule uses for operator entries.
func TestProcessPolicyStore_NilConfigStoreIsInMemory(t *testing.T) {
	ctx := context.Background()
	s := NewProcessPolicyStore(nil)
	def := policy(pb.ProcessAction_PROCESS_ACTION_THROTTLE, "", 0)
	if err := s.SetDefault(ctx, def); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	got, err := s.Default(ctx)
	if err != nil || !proto.Equal(got, def) {
		t.Fatalf("Default() = %v, %v; want %v", got, err, def)
	}
}

// A database failure is an error, never a silent fall-through to the
// built-in default: the daemon must not act on ALERT believing THROTTLE was
// never configured.
func TestProcessPolicyStore_BackendErrorSurfaces(t *testing.T) {
	s := NewProcessPolicyStore(&fakeConfigStore{err: errors.New("db down")})
	if _, err := s.Effective(context.Background(), "box-a"); err == nil {
		t.Fatal("Effective() = nil error, want the store failure")
	}
}

// TestResolveProcessPolicy_KillProcess (#2638): kill_process is off unless a
// level sets it; an unset level inherits; an explicit false on an override
// turns a backend-default true back off.
func TestResolveProcessPolicy_KillProcess(t *testing.T) {
	on, off := proto.Bool(true), proto.Bool(false)
	tests := []struct {
		name              string
		override, backend *bool
		want              bool
	}{
		{"nothing set", nil, nil, false},
		{"backend true", nil, on, true},
		{"override true", on, nil, true},
		{"override false beats backend true", off, on, false},
		{"unset override inherits backend true", nil, on, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ov, be *pb.ProcessPolicy
			if tt.override != nil {
				ov = &pb.ProcessPolicy{KillProcess: tt.override}
			}
			if tt.backend != nil {
				be = &pb.ProcessPolicy{KillProcess: tt.backend}
			}
			got := ResolveProcessPolicy(ov, be)
			if got.KillProcess == nil || got.GetKillProcess() != tt.want {
				t.Fatalf("kill_process = %v, want %v (explicitly set)", got.KillProcess, tt.want)
			}
		})
	}
	if BuiltinProcessPolicy().GetKillProcess() {
		t.Fatal("built-in policy kills processes; kill_process must default to false")
	}
}

func TestRespondsTo(t *testing.T) {
	tests := []struct {
		rule pb.ThreatRuleId
		want bool
	}{
		{pb.ThreatRuleId_THREAT_RULE_ID_MINING_BEHAVIOR, true},
		{pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE, true},
		{pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION, false},
		{pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST, false},
		{pb.ThreatRuleId_THREAT_RULE_ID_PROCESS_ACTION_EXPIRED, false},
	}
	for _, tt := range tests {
		if got := RespondsTo(tt.rule); got != tt.want {
			t.Errorf("RespondsTo(%v) = %v, want %v", tt.rule, got, tt.want)
		}
	}
	if !KillsProcess(pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE) || KillsProcess(pb.ThreatRuleId_THREAT_RULE_ID_MINING_BEHAVIOR) {
		t.Error("only the miner-signature rule may kill a process")
	}
}

// THROTTLE must be a hard CFS quota. Incus reads a bare "N%" as a soft share
// (cpu.weight) that does nothing on an uncontended host and drops the box's
// existing hard cap, so "N%" means N percent of ONE core and is applied as
// "Nms/100ms" (#2676).
func TestHardThrottleAllowance(t *testing.T) {
	tests := []struct {
		name, in, prev, want string
		wantErr              bool
	}{
		{name: "percent of one core becomes a hard quota", in: "10%", want: "10ms/100ms"},
		{name: "100 percent is one whole core", in: "100%", want: "100ms/100ms"},
		{name: "explicit quota is kept", in: "25ms/100ms", want: "25ms/100ms"},
		{name: "explicit quota with another period is kept", in: "50ms/200ms", want: "50ms/200ms"},
		{name: "never looser than the box's existing hard cap", in: "10%", prev: "5ms/100ms", want: "5ms/100ms"},
		{name: "tighter than the existing cap wins", in: "10%", prev: "200ms/100ms", want: "10ms/100ms"},
		{name: "a soft previous allowance does not loosen it", in: "10%", prev: "50%", want: "10ms/100ms"},
		{name: "no previous allowance", in: "10%", prev: "", want: "10ms/100ms"},
		{name: "garbage is rejected", in: "ten", wantErr: true},
		{name: "zero percent is rejected", in: "0%", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HardThrottleAllowance(tt.in, tt.prev)
			if (err != nil) != tt.wantErr {
				t.Fatalf("HardThrottleAllowance(%q, %q) err = %v, wantErr %v", tt.in, tt.prev, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("HardThrottleAllowance(%q, %q) = %q, want %q", tt.in, tt.prev, got, tt.want)
			}
			if err == nil && strings.Contains(got, "%") {
				t.Errorf("result %q still a soft percentage share", got)
			}
		})
	}
}
