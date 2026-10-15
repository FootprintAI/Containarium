package cmd

import (
	"os"
	"strconv"

	"github.com/footprintai/containarium/internal/guardrailrate"
	"github.com/footprintai/containarium/internal/server"
)

// Per-subject rate limits on the guardrail APIs (#2404). A rate of 0
// disables that limit; a burst of 0 defaults to the per-minute rate.
// Documented in docs/architecture/guardrail-inbound-and-server-policy.md
// ("Rate limits").
var (
	daemonGuardrailDeployRate, daemonGuardrailPolicySetRate, daemonGuardrailPolicyGetRate    float64
	daemonGuardrailDeployBurst, daemonGuardrailPolicySetBurst, daemonGuardrailPolicyGetBurst int
)

func init() {
	fl := daemonCmd.Flags()
	fl.Float64Var(&daemonGuardrailDeployRate, "guardrail-deploy-rate-per-minute", envFloat("CONTAINARIUM_GUARDRAIL_DEPLOY_RATE_PER_MINUTE", 6),
		"Guardrail-gated recipe deploys allowed per caller per minute; over it a deploy is RESOURCE_EXHAUSTED before any snapshot. 0 disables. Env: CONTAINARIUM_GUARDRAIL_DEPLOY_RATE_PER_MINUTE (#2404)")
	fl.IntVar(&daemonGuardrailDeployBurst, "guardrail-deploy-burst", envInt("CONTAINARIUM_GUARDRAIL_DEPLOY_BURST", 3),
		"Gated deploys a caller may make back to back before the per-minute rate applies. 0 = the per-minute rate. Env: CONTAINARIUM_GUARDRAIL_DEPLOY_BURST (#2404)")
	fl.Float64Var(&daemonGuardrailPolicySetRate, "guardrail-policy-set-rate-per-minute", envFloat("CONTAINARIUM_GUARDRAIL_POLICY_SET_RATE_PER_MINUTE", 10),
		"Guardrail policy Sets allowed per caller per minute (admins are not exempt). 0 disables. Env: CONTAINARIUM_GUARDRAIL_POLICY_SET_RATE_PER_MINUTE (#2404)")
	fl.IntVar(&daemonGuardrailPolicySetBurst, "guardrail-policy-set-burst", envInt("CONTAINARIUM_GUARDRAIL_POLICY_SET_BURST", 10),
		"Guardrail policy Set burst per caller. 0 = the per-minute rate. Env: CONTAINARIUM_GUARDRAIL_POLICY_SET_BURST (#2404)")
	fl.Float64Var(&daemonGuardrailPolicyGetRate, "guardrail-policy-get-rate-per-minute", envFloat("CONTAINARIUM_GUARDRAIL_POLICY_GET_RATE_PER_MINUTE", 120),
		"Guardrail policy Gets (including 'guardrail apply/verify' policy reads) allowed per caller per minute. 0 disables. Env: CONTAINARIUM_GUARDRAIL_POLICY_GET_RATE_PER_MINUTE (#2404)")
	fl.IntVar(&daemonGuardrailPolicyGetBurst, "guardrail-policy-get-burst", envInt("CONTAINARIUM_GUARDRAIL_POLICY_GET_BURST", 120),
		"Guardrail policy Get burst per caller. 0 = the per-minute rate. Env: CONTAINARIUM_GUARDRAIL_POLICY_GET_BURST (#2404)")
}

// daemonGuardrailRateLimits is the flags as the server's typed config.
func daemonGuardrailRateLimits() server.GuardrailRateLimits {
	return server.GuardrailRateLimits{
		Deploy:    guardrailrate.Limit{PerMinute: daemonGuardrailDeployRate, Burst: daemonGuardrailDeployBurst},
		PolicySet: guardrailrate.Limit{PerMinute: daemonGuardrailPolicySetRate, Burst: daemonGuardrailPolicySetBurst},
		PolicyGet: guardrailrate.Limit{PerMinute: daemonGuardrailPolicyGetRate, Burst: daemonGuardrailPolicyGetBurst},
	}
}

// envInt reads name as an int, returning def when unset or unparseable
// (envFloat's convention: a typo leaves the documented default in force).
func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
