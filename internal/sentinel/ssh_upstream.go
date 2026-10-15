package sentinel

import (
	"fmt"
	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	"net"
	"os"
	"strconv"
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
	m.sshUpstream = controller
	return func() { stop(); _ = controller.Close() }, nil
}
