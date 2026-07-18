package config

// BYOC (bring-your-own-compute) host-daemon variable names.
//
// CONTAINARIUM_BYOC_INGRESS_ADDR opts a host into the sentinel-terminate BYOC
// public-HTTP-ingress data path (#733 slice 3). When set to a loopback-scoped
// address ("127.0.0.1:<port>"), the daemon's edge Caddy adds one extra plaintext
// listener there that serves the same Host-matched routes as :443 but WITHOUT
// TLS. The sentinel terminates TLS with the wildcard it holds and
// plaintext-forwards over the tunnel to this listener, which Host-routes to the
// box — so the BYOC host needs no cert. Empty (default) = disabled: region hosts
// and non-BYOC deployments are unchanged.
//
// MUST be loopback-scoped so it is reachable only via the tunnel client (which
// dials 127.0.0.1:<port>) and never from the LAN — it serves tenant routes in
// the clear.
const EnvBYOCIngressAddr = "CONTAINARIUM_BYOC_INGRESS_ADDR"

// DefaultBYOCIngressAddr is the conventional loopback address to set
// CONTAINARIUM_BYOC_INGRESS_ADDR to on a BYOC host. 8081 avoids the edge's :80
// (HTTP→HTTPS redirect) and :443 (TLS), so automatic-HTTPS redirects don't apply
// and the listener serves reverse_proxy routes directly as plaintext.
const DefaultBYOCIngressAddr = "127.0.0.1:8081"
