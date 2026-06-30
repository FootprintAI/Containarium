package config

// CONTAINARIUM_WAF_* variable names — the in-daemon WAF (tproxy inspection +
// ingress). WAF_INSPECT / WAF_INGRESS use the shared truthy convention
// (1/true/yes/on) at their read sites.
const (
	EnvWAFTProxyAddr = "CONTAINARIUM_WAF_TPROXY_ADDR"
	EnvWAFInspect    = "CONTAINARIUM_WAF_INSPECT"
	EnvWAFIngress    = "CONTAINARIUM_WAF_INGRESS"
)
