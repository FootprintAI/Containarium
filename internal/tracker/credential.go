// Package tracker will hold the daemon-side tracker broker — agent-visible
// GitHub/GitLab issue and change-request verbs backed by a daemon-custody
// credential (#1920). This file lands ahead of the rest of the package
// (#1922, #1923) because the broker-only secret mode (#1921) needs a
// named seam to plug into. See docs/architecture/agent-tracker-broker.md.
package tracker

import "context"

// CredentialSource resolves a tenant's stored broker credential by secret
// name. Satisfied by *secrets.Store's BrokerCredential method.
//
// internal/tracker depends on this interface rather than importing
// internal/secrets directly for the credential read, so moving credential
// custody out of the daemon later (the documented fallback if D1 is
// declined — see the architecture doc's "Rejected alternatives") is a
// wiring change at the construction site, not a rewrite of the broker
// core.
type CredentialSource interface {
	// BrokerCredential returns the plaintext value of the named
	// broker-only secret owned by tenant. Implementations refuse (a
	// distinguishable error) a secret that is not in broker-only mode.
	BrokerCredential(ctx context.Context, tenant, secretName string) (string, error)
}
