package sentinel

import (
	"fmt"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
)

// #2415 — the pieces of the SSH session shipper that live in the sentinel
// process: its backend pool (id -> address), keysync's login -> backend
// routing, and the audit-ingest token file. internal/cmd assembles them with
// the typed client and runs the loop (see startSSHSessionShipper).

// FileAuditIngestTokens is a sshsession.TokenSource over the audit-ingest
// token file. It re-reads the file on every call, so a token registered or
// rotated with `sentinel register-token --kind audit-ingest` takes effect on
// the next pass with no restart.
type FileAuditIngestTokens struct {
	Path string
}

// TokenFor returns backendID's registered token.
func (f FileAuditIngestTokens) TokenFor(backendID string) (string, bool, error) {
	entries, err := LoadAuditIngestTokenStore(f.Path)
	if err != nil {
		return "", false, err
	}
	for _, e := range entries {
		if e.BackendID == backendID {
			return e.Token, true, nil
		}
	}
	return "", false, nil
}

// Backends lists every backend that has a registered token.
func (f FileAuditIngestTokens) Backends() ([]string, error) {
	entries, err := LoadAuditIngestTokenStore(f.Path)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.BackendID
	}
	return out, nil
}

// ShipperBackendURL is the REST base URL of a backend's daemon, the same
// address keysync polls (backend IP + the sentinel's health port, where the
// daemon's gateway also serves /v1/...). The shipper's client is built from it
// in internal/cmd, not here: this package must not import internal/client
// (internal/client's tests import internal/server, which imports this
// package — an import cycle in the test build).
func (m *Manager) ShipperBackendURL(backendID string) (string, error) {
	b := m.backends.Get(backendID)
	if b == nil {
		return "", fmt.Errorf("backend %q is not in the sentinel's pool", backendID)
	}
	return fmt.Sprintf("http://%s:%d", b.IP, m.config.HealthPort), nil
}

// SSHSessionBackendResolver maps a record's login to the backend sshpiper
// routed it to, by keysync's own rule.
func (m *Manager) SSHSessionBackendResolver() sshsession.BackendResolver {
	return m.keyStore
}

// AuditIngestTokens is the shipper's token source: the register-token store,
// re-read on every call.
func (m *Manager) AuditIngestTokens() sshsession.TokenSource {
	return FileAuditIngestTokens{Path: m.AuditIngestTokenStorePath()}
}
