//go:build !windows && !containarium_client

package cmd

import "fmt"

// baseDomainSource names where the daemon's effective --base-domain came from.
type baseDomainSource string

const (
	baseDomainFromDefault baseDomainSource = "default"       // the flag's built-in default
	baseDomainFromFlag    baseDomainSource = "flag"          // --base-domain on the command line
	baseDomainFromDB      baseDomainSource = "daemon_config" // stored in the local Postgres on an earlier start
)

// byocBaseDomainWarning returns the startup warning for a --byoc-backend host
// that holds a base domain, or "" when there is nothing to warn about (#2262).
// The daemon serves no base domain on such a host, but a value that was
// passed or stored is still worth naming: it is how the host got into the
// state #2262 describes, and the stored one survives until it is cleared.
// The built-in default is not reported: nothing set it.
func byocBaseDomainWarning(byoc bool, value string, src baseDomainSource) string {
	if !byoc || value == "" || src == baseDomainFromDefault {
		return ""
	}
	how := "it is stored in daemon_config from an earlier start, and survives removing the flag; " +
		"clear it as in docs/BYOC-BACKEND-BRINGUP.md once the host has no ingress routes"
	if src == baseDomainFromFlag {
		how = "drop --base-domain from this host's daemon unit"
	}
	return fmt.Sprintf("WARNING: --byoc-backend: base domain %q (from %s) is NOT served: no management apex route, "+
		"no certificate for it, nothing advertised for it. Serving a base domain on a BYOC backend made the local Caddy "+
		"claim a name this host does not own, failing its certificate order and every TLS handshake (#2262). "+
		"The value is used only to keep existing ingress route IDs stable. To remove it: %s.", value, src, how)
}
