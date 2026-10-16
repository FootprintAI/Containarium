package sentinel

import (
	"context"
	"fmt"
	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// BackendForEndpoint resolves enforcement identity from authoritative key routes.
func (ks *KeyStore) BackendForEndpoint(endpoint string) (string, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	id := ""
	for _, b := range ks.backends {
		if net.JoinHostPort(b.backendIP, strconv.Itoa(routeTargetPort(b.backendIP, b.sshPort))) == endpoint {
			if id != "" && id != b.backendID {
				return "", fmt.Errorf("ambiguous SSH endpoint")
			}
			id = b.backendID
		}
	}
	if id == "" {
		return "", fmt.Errorf("unknown SSH route %s", endpoint)
	}
	return id, nil
}

// startSSHUpstream owns the shared private controller for the Manager lifetime.
func (m *Manager) startSSHUpstream() (func(), error) {
	if m.config.SSHUpstreamPolicy == "" {
		return func() {}, nil
	}
	data, err := os.ReadFile(m.config.SSHUpstreamPolicy)
	if err != nil {
		return nil, err
	}
	policy, err := sshcontrol.ParsePolicy(data)
	if err != nil {
		return nil, err
	}
	state, socket := m.config.SSHUpstreamState, m.config.SSHUpstreamSocket
	if state == "" {
		state = sshcontrol.DefaultState
	}
	if socket == "" {
		socket = sshcontrol.DefaultSocket
	}
	controller, err := sshcontrol.New(sshcontrol.Config{Policy: policy, StatePath: state, Resolve: m.keyStore.BackendForEndpoint})
	if err != nil {
		return nil, err
	}
	stop, err := sshcontrol.ListenControl(socket, controller)
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	m.sshUpstreamMu.Lock()
	m.sshUpstream = controller
	m.sshUpstreamMu.Unlock()
	return func() { stop(); _ = controller.Close() }, nil
}

// sshUpstreamController snapshots the owner without racing startup retries.
func (m *Manager) sshUpstreamController() *sshcontrol.Controller {
	m.sshUpstreamMu.RLock()
	defer m.sshUpstreamMu.RUnlock()
	return m.sshUpstream
}

// superviseSSHUpstream isolates guard faults and retries without resetting risk.
func (m *Manager) superviseSSHUpstream(ctx context.Context, interval time.Duration) func() {
	if m.config.SSHUpstreamPolicy == "" {
		return func() {}
	}
	var stop func()
	retry := func() {
		if c := m.sshUpstreamController(); c != nil {
			if c.Faulted() {
				if err := c.Recover(); err != nil {
					log.Printf("[sentinel] SSH upstream fault remains: %v", err)
				}
			}
			return
		}
		var err error
		stop, err = m.startSSHUpstream()
		m.sshUpstreamStartupFault.Store(err != nil)
		if err != nil {
			log.Printf("[sentinel] SSH guard unavailable; other services continue: %v", err)
		}
	}
	retry()
	worker, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-worker.Done():
				return
			case <-ticker.C:
				retry()
			}
		}
	}()
	return func() {
		cancel()
		<-done
		if stop != nil {
			stop()
		}
	}
}
