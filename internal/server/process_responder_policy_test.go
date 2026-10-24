package server

import (
	"context"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// countingPolicyConfig is an in-memory PolicyConfigStore that counts reads.
type countingPolicyConfig struct {
	mu   sync.Mutex
	kv   map[string]string
	gets int
}

func (c *countingPolicyConfig) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	v, ok := c.kv[key]
	if !ok {
		return "", app.ErrDaemonConfigNotFound
	}
	return v, nil
}

func (c *countingPolicyConfig) Set(_ context.Context, key, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kv[key] = value
	return nil
}

func (c *countingPolicyConfig) reads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets
}

// TestProcessResponder_ReadsPolicyOncePerFinding (#2768 item 5): the kill
// step and the policy action share one resolution of the effective policy.
// One Effective is two config reads (backend default, box override).
func TestProcessResponder_ReadsPolicyOncePerFinding(t *testing.T) {
	for _, action := range []pb.ProcessAction{pb.ProcessAction_PROCESS_ACTION_ALERT, pb.ProcessAction_PROCESS_ACTION_THROTTLE} {
		t.Run(action.String(), func(t *testing.T) {
			fx := newResponderFixture(t, false)
			cfg := &countingPolicyConfig{kv: map[string]string{}}
			fx.policies = threatdetect.NewProcessPolicyStore(cfg)
			fx.r.policies = fx.policies
			fx.setDefault(t, action, "", 0)
			fx.setKill(t, "", true)
			k := &fakeKiller{}
			fx.r.SetProcessKiller(k)

			before := cfg.reads()
			f := fx.fireSignature(t, "box-a", 4242)
			if len(k.calls) != 1 || f.Response == nil || !f.Response.ProcessKilled {
				t.Fatalf("kills=%v response=%+v, want the process killed", k.calls, f.Response)
			}
			if n := cfg.reads() - before; n != 2 {
				t.Fatalf("policy config read %d times for one finding, want 2 (one Effective)", n)
			}
		})
	}
}

// TestProcessResponder_UnreadablePolicySkipsKillAndAction: with the policy
// store failing, the one read fails for both steps: the kill is skipped as
// POLICY_UNREADABLE and no policy action is applied.
func TestProcessResponder_UnreadablePolicySkipsKillAndAction(t *testing.T) {
	fx := newResponderFixture(t, false)
	kv := &flakyPolicyKV{m: map[string]string{}}
	fx.policies = threatdetect.NewProcessPolicyStore(kv)
	fx.r.policies = fx.policies
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 0)
	fx.setKill(t, "", true)
	k := &fakeKiller{}
	fx.r.SetProcessKiller(k)
	kv.mu.Lock()
	kv.fail = true
	kv.mu.Unlock()

	f := fx.fireSignature(t, "box-a", 4242)
	if len(k.calls) != 0 || setCPUCalls(fx) != 0 {
		t.Fatalf("kills=%v throttles=%d with an unreadable policy, want none", k.calls, setCPUCalls(fx))
	}
	if f.Response == nil || f.Response.KillSkipReason != pb.KillSkipReason_KILL_SKIP_REASON_POLICY_UNREADABLE {
		t.Fatalf("response = %+v, want kill skipped POLICY_UNREADABLE", f.Response)
	}
}
