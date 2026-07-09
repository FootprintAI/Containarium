package config

import (
	"fmt"
	"strconv"
)

// CONTAINARIUM_SENTINEL_* variable names. These constants are the single source
// of truth for the sentinel namespace — reference them instead of string
// literals so each name is defined in exactly one place.
const (
	EnvSentinelAddr         = "CONTAINARIUM_SENTINEL_ADDR"
	EnvSentinelAlertWebhook = "CONTAINARIUM_SENTINEL_ALERT_WEBHOOK"
	// #nosec G101 -- this is the NAME of an environment variable, not a credential value.
	EnvSentinelAuthSecret = "CONTAINARIUM_SENTINEL_AUTH_SECRET"
	// #nosec G101 -- this is the NAME of an environment variable, not a credential value.
	//
	// Deliberately separate from EnvSentinelAuthSecret: the auth secret is
	// held by every daemon in the cluster (keysync/certsync), so reusing it
	// here would let a compromised daemon mint tunnel-join tokens for any
	// pool. This secret is held only by whoever is trusted to admit new
	// nodes — an operator, or the cloud control plane's token-issuance
	// service. See sentinel.TunnelTokenRegisterHandler.
	EnvSentinelAdminSecret = "CONTAINARIUM_SENTINEL_ADMIN_SECRET"
	EnvSentinelCertSANs    = "CONTAINARIUM_SENTINEL_CERT_SANS"
	EnvSentinelHost        = "CONTAINARIUM_SENTINEL_HOST"
	EnvSentinelHTTPSPort   = "CONTAINARIUM_SENTINEL_HTTPS_PORT"
	EnvSentinelPublicKey   = "CONTAINARIUM_SENTINEL_PUBLIC_KEY"
	EnvSentinelSigningKey  = "CONTAINARIUM_SENTINEL_SIGNING_KEY"
	EnvSentinelURL         = "CONTAINARIUM_SENTINEL_URL"
)

// Sentinel is the typed view of the CONTAINARIUM_SENTINEL_* namespace — the
// always-on gateway VM that fronts the spot/backend daemons. Load it once at
// startup with LoadSentinel and pass it where these values are needed instead
// of re-reading the environment.
type Sentinel struct {
	// Addr is the sentinel address (host:port) that `containarium node` dials.
	// (EnvSentinelAddr)
	Addr string

	// AlertWebhook is POSTed on spot preempted/recovered. It is the always-on
	// alert path: the on-spot vmalert dies with the VM, so the sentinel owns it.
	// (EnvSentinelAlertWebhook)
	AlertWebhook string

	// AuthSecret is the shared HMAC secret that authenticates keysync/certsync
	// and peer discovery between the sentinel and the daemons. Empty disables
	// auth (every such request 401s). Minimum strength is enforced at the auth
	// boundary (auth.SentinelMinSecretLen / Manager.HMACSecretConfigured), not
	// here. (EnvSentinelAuthSecret)
	AuthSecret string

	// CertSANs is a comma-separated list of extra SANs added to the sentinel's
	// peer-CA-issued server certificate. (EnvSentinelCertSANs)
	CertSANs string

	// Host is the sentinel SSH host that provisioning / sync / push SSH into to
	// reach boxes. (EnvSentinelHost)
	Host string

	// HTTPSPort overrides the sentinel binary server's HTTPS listener port
	// (default: the HTTP port + 1). Kept as the raw string so the caller can
	// preserve its own parse-error logging and dynamic default. Validate checks
	// it is a usable port when set. (EnvSentinelHTTPSPort)
	HTTPSPort string

	// PublicKey is the sentinel's base64 ed25519 public key that daemons pin for
	// peer discovery. (EnvSentinelPublicKey)
	PublicKey string

	// SigningKey is the sentinel's base64 ed25519 private signing key.
	// (EnvSentinelSigningKey)
	SigningKey string

	// URL is the sentinel base URL daemons point at for peer discovery, cert
	// issuance, and binary download (http:// or https://). (EnvSentinelURL)
	URL string
}

// LoadSentinel reads the CONTAINARIUM_SENTINEL_* namespace from the environment
// once. Fields are empty when unset; defaults that depend on other runtime
// values (e.g. HTTPSPort = HTTP port + 1) stay at the call site.
func LoadSentinel() Sentinel {
	return Sentinel{
		Addr:         getString(EnvSentinelAddr, ""),
		AlertWebhook: getString(EnvSentinelAlertWebhook, ""),
		AuthSecret:   getString(EnvSentinelAuthSecret, ""),
		CertSANs:     getString(EnvSentinelCertSANs, ""),
		Host:         getString(EnvSentinelHost, ""),
		HTTPSPort:    getString(EnvSentinelHTTPSPort, ""),
		PublicKey:    getString(EnvSentinelPublicKey, ""),
		SigningKey:   getString(EnvSentinelSigningKey, ""),
		URL:          getString(EnvSentinelURL, ""),
	}
}

// Validate reports configuration errors that should fail daemon startup rather
// than surface deep inside a request. It is intentionally light: secret-strength
// checks belong at the auth boundary (auth.SentinelMinSecretLen). Today it only
// verifies that HTTPSPort, when set, parses as a valid TCP port.
func (s Sentinel) Validate() error {
	if s.HTTPSPort != "" {
		p, err := strconv.Atoi(s.HTTPSPort)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("%s=%q is not a valid TCP port (1-65535)", EnvSentinelHTTPSPort, s.HTTPSPort)
		}
	}
	return nil
}
