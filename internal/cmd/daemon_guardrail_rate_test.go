package cmd

import (
	"strings"
	"testing"
)

// TestDaemonGuardrailRateFlags pins the documented defaults of the guardrail
// rate limits (#2404) and that each names its env override.
func TestDaemonGuardrailRateFlags(t *testing.T) {
	for _, tc := range []struct{ flag, def, env string }{
		{"guardrail-deploy-rate-per-minute", "6", "CONTAINARIUM_GUARDRAIL_DEPLOY_RATE_PER_MINUTE"},
		{"guardrail-deploy-burst", "3", "CONTAINARIUM_GUARDRAIL_DEPLOY_BURST"},
		{"guardrail-policy-set-rate-per-minute", "10", "CONTAINARIUM_GUARDRAIL_POLICY_SET_RATE_PER_MINUTE"},
		{"guardrail-policy-set-burst", "10", "CONTAINARIUM_GUARDRAIL_POLICY_SET_BURST"},
		{"guardrail-policy-get-rate-per-minute", "120", "CONTAINARIUM_GUARDRAIL_POLICY_GET_RATE_PER_MINUTE"},
		{"guardrail-policy-get-burst", "120", "CONTAINARIUM_GUARDRAIL_POLICY_GET_BURST"},
	} {
		f := daemonCmd.Flags().Lookup(tc.flag)
		if f == nil {
			t.Errorf("--%s is not registered", tc.flag)
			continue
		}
		if f.DefValue != tc.def {
			t.Errorf("--%s default = %s, want %s", tc.flag, f.DefValue, tc.def)
		}
		if !strings.Contains(f.Usage, tc.env) {
			t.Errorf("--%s usage %q does not name its env override %s", tc.flag, f.Usage, tc.env)
		}
	}
}

// TestDaemonGuardrailRateLimits: the flags reach the server config as typed
// limits.
func TestDaemonGuardrailRateLimits(t *testing.T) {
	got := daemonGuardrailRateLimits()
	if got.Deploy.PerMinute != 6 || got.Deploy.Burst != 3 ||
		got.PolicySet.PerMinute != 10 || got.PolicySet.Burst != 10 ||
		got.PolicyGet.PerMinute != 120 || got.PolicyGet.Burst != 120 {
		t.Fatalf("daemonGuardrailRateLimits() = %+v, want the documented defaults", got)
	}
}
