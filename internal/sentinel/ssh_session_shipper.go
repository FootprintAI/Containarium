package sentinel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
)

// #2415 — runs the SSH session shipper inside the sentinel process.
//
// It lives here, not in a separate unit, because everything the shipper
// needs is already in this process: the backend pool (id -> address), the
// keysync login -> backend routing, and the audit-ingest token file.

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

// SSHSessionShipperOptions configures Manager.StartSSHSessionShipper.
type SSHSessionShipperOptions struct {
	RecordsFile    string
	CheckpointFile string
	Interval       time.Duration
	SentinelID     string
	DefaultBackend string
}

// shipperBackendURL is the REST base URL of a backend's daemon, the same
// address keysync polls (backend IP + the sentinel's health port, where the
// daemon's gateway also serves /v1/...).
func (m *Manager) shipperBackendURL(backendID string) (string, error) {
	b := m.backends.Get(backendID)
	if b == nil {
		return "", fmt.Errorf("backend %q is not in the sentinel's pool", backendID)
	}
	return fmt.Sprintf("http://%s:%d", b.IP, m.config.HealthPort), nil
}

// ShipConfig assembles the shipper's configuration from this manager's own
// state.
func (m *Manager) ShipConfig(opts SSHSessionShipperOptions) sshsession.ShipConfig {
	return sshsession.ShipConfig{
		RecordsFile:    opts.RecordsFile,
		CheckpointFile: opts.CheckpointFile,
		SentinelID:     opts.SentinelID,
		DefaultBackend: opts.DefaultBackend,
		Resolver:       m.keyStore,
		Tokens:         FileAuditIngestTokens{Path: m.AuditIngestTokenStorePath()},
		NewClient: func(backendID, token string) (sshsession.IngestClient, error) {
			base, err := m.shipperBackendURL(backendID)
			if err != nil {
				return nil, err
			}
			return client.NewHTTPClient(base, token)
		},
		Rejected: client.IsIngestRejected,
		Logf:     func(format string, args ...any) { log.Printf("[sentinel] ssh-session-shipper: "+format, args...) },
	}
}

// StartSSHSessionShipper runs the shipper loop in the background until ctx
// is cancelled or the returned stop func is called (which waits for the
// loop to exit, so an in-flight batch finishes or is abandoned before the
// sentinel does).
func (m *Manager) StartSSHSessionShipper(ctx context.Context, opts SSHSessionShipperOptions) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	cfg := m.ShipConfig(opts)
	go func() {
		defer close(done)
		log.Printf("[sentinel] ssh-session-shipper started (records=%s checkpoint=%s interval=%s)", opts.RecordsFile, opts.CheckpointFile, opts.Interval)
		if err := sshsession.Ship(ctx, cfg, opts.Interval); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[sentinel] ssh-session-shipper stopped: %v", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
