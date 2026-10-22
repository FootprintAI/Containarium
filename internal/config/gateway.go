package config

// CONTAINARIUM_GATEWAY_* variable names — the model/output gateway.
const (
	// EnvGatewayOutputFilter — output filtering is on unless set to "0".
	EnvGatewayOutputFilter = "CONTAINARIUM_GATEWAY_OUTPUT_FILTER"

	// EnvGatewayNoGlobalKeyFallback ("1") makes a gateway token that carries a
	// key_owner resolve ONLY through its owner's key. With it set, an owner with
	// no key is refused instead of falling back to a daemon-global provider key
	// (<PROVIDER>_API_KEY) and being billed to the operator. Unset keeps the
	// fallback, which self-hosted daemons running on one global key rely on; a
	// multi-tenant daemon sets it. Tokens without a key_owner are unaffected.
	EnvGatewayNoGlobalKeyFallback = "CONTAINARIUM_GATEWAY_NO_GLOBAL_KEY_FALLBACK"

	// Per-tenant quota. All unset ⇒ no budget ⇒ nothing is ever denied on
	// quota grounds, which is the behavior of every daemon before these
	// existed. A deployment opts in by naming numbers.
	//
	// EnvGatewayQuotaWindow is the rolling period the caps apply over, as a Go
	// duration ("1m", "1h"). Defaults to 1m when any cap is set.
	EnvGatewayQuotaWindow = "CONTAINARIUM_GATEWAY_QUOTA_WINDOW"
	// EnvGatewayQuotaCalls caps model calls per tenant per window.
	EnvGatewayQuotaCalls = "CONTAINARIUM_GATEWAY_QUOTA_CALLS"
	// EnvGatewayQuotaTokens caps input+output+cached tokens per tenant per window.
	EnvGatewayQuotaTokens = "CONTAINARIUM_GATEWAY_QUOTA_TOKENS" // #nosec G101 -- env var name, not a credential value
	// EnvGatewayQuotaOutputTokens caps generated tokens per tenant per window.
	EnvGatewayQuotaOutputTokens = "CONTAINARIUM_GATEWAY_QUOTA_OUTPUT_TOKENS" // #nosec G101 -- env var name, not a credential value

	// EnvGatewayAnomalyEnabled turns the per-tenant anomaly detectors on ("1").
	// Off by default: the detectors are advisory input to the response ladder,
	// and an operator should choose to act on heuristics rather than inherit
	// them in a patch release.
	EnvGatewayAnomalyEnabled = "CONTAINARIUM_GATEWAY_ANOMALY"

	// EnvGatewayAnomalyRevokeAt is the anomaly score (0..1] at which a tenant is
	// revoked automatically. Unset ⇒ never: revocation needs a human to undo,
	// so it is not something a heuristic should reach on its own unless the
	// operator has explicitly asked for that.
	EnvGatewayAnomalyRevokeAt = "CONTAINARIUM_GATEWAY_ANOMALY_REVOKE_AT"
)
