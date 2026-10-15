package sentinel

import (
	"net/http"
	"os"

	"github.com/footprintai/containarium/internal/sentinel/sshban"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// sshBanHandler discovers enabled local listeners and forwards to their private
// control sockets. Tests inject sockets without altering host provisioning.
func (m *Manager) sshBanHandler() http.Handler {
	return (&sshban.Proxy{ResolveSocket: m.sshBanSocket}).Handler()
}

// sshBanSocket discovers the anonymous unit at request time, because enabling
// that listener through metadata need not restart the separate sentinel daemon.
func (m *Manager) sshBanSocket(listener pb.SSHBanListener) string {
	if m.sshBanSockets != nil {
		return m.sshBanSockets[listener]
	}
	if listener == pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS {
		if _, err := os.Stat("/etc/systemd/system/sshpiper-anon.service"); err != nil {
			return ""
		}
	}
	return sshban.DefaultSocket(listener)
}
