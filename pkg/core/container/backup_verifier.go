package container

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// CreateBackupVerifier creates a fresh, daemon-owned Postgres container for
// one verification. It does not create a tenant login or copy source data or
// configuration. The caller must authorize tenant before calling and always
// invoke cleanup. A unique name keeps concurrent verifications isolated.
func (m *Manager) CreateBackupVerifier(tenant string) (name, password string, cleanup func() error, err error) {
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return
	}
	name = "backup-verify-" + hex.EncodeToString(nonce[:12]) + "-container"
	password = hex.EncodeToString(nonce[12:])
	image := os.Getenv("CONTAINARIUM_BACKUP_VERIFY_IMAGE")
	if image == "" {
		image = "images:ubuntu/24.04"
	}
	err = m.incus.CreateContainer(incus.ContainerConfig{
		Name: name, Image: image, CPU: "2", Memory: "1GB",
		Disk: &incus.DiskDevice{Path: "/", Pool: m.incus.StoragePool(), Size: "20GB"},
		ExtraConfig: map[string]string{
			incus.TenantLabelKey:                  tenant,
			incus.LabelPrefix + "backup-verifier": "true",
			incus.TTLExpiresAtKey:                 time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		return
	}
	cleanup = func() error {
		// Also try deletion if start failed or the container already stopped.
		_ = m.incus.StopContainer(name, true)
		return m.incus.DeleteContainer(name)
	}
	defer func() {
		if err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				err = fmt.Errorf("%w; cleanup: %v", err, cleanupErr)
			}
		}
	}()
	if err = m.incus.StartContainer(name); err != nil {
		return
	}
	if _, err = m.incus.WaitForNetwork(name, 90*time.Second); err != nil {
		return
	}
	// The password is generated hex, never caller input. PostgreSQL listens
	// only on loopback; verification receives these connection settings rather
	// than caller-supplied hosts or source credentials.
	script := `set -eu
if command -v cloud-init >/dev/null 2>&1; then cloud-init status --wait; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq postgresql-16
pg_conftool 16 main set listen_addresses 127.0.0.1
pg_ctlcluster 16 main restart
pg_isready -q
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "ALTER USER postgres PASSWORD '` + password + `'"
`
	_, stderr, exitCode, execErr := m.incus.ExecWithExitCode(name, []string{"sh", "-c", script})
	if execErr != nil || exitCode != 0 {
		err = fmt.Errorf("provision backup verifier %s (exit %d): %v: %s", name, exitCode, execErr, stderr)
	}
	return
}
