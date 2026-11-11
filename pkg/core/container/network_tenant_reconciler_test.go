package container

import (
	"errors"
	"fmt"
	"testing"

	"github.com/footprintai/containarium/internal/nicguard"
	"github.com/footprintai/containarium/internal/tenantguard"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/lxc/incus/v7/shared/api"
)

type nativeBirthBackend struct {
	*guardBackend
	acl        *incus.ACLConfig
	attached   string
	nicKeys    map[string]string
	failAttach bool
	cleanupErr error
}

func (b *nativeBirthBackend) GetServerInfo() (*api.Server, error) {
	return &api.Server{ServerUntrusted: api.ServerUntrusted{APIExtensions: []string{"network_acl", "network_bridge_acl", "network_bridge_acl_devices"}}, Environment: api.ServerEnvironment{Firewall: "nftables", ServerVersion: "7.5"}}, nil
}
func (b *nativeBirthBackend) ListContainers() ([]incus.ContainerInfo, error) {
	return []incus.ContainerInfo{{Name: b.createdConfig.Name, Tenant: b.createdConfig.ExtraConfig[incus.TenantLabelKey], Managed: true}}, nil
}
func (b *nativeBirthBackend) GetNetworkACL(string) (*api.NetworkACL, error) {
	return nil, errors.New("fixture: absent ACL")
}
func (b *nativeBirthBackend) CreateNetworkACL(cfg incus.ACLConfig) error    { b.acl = &cfg; return nil }
func (b *nativeBirthBackend) EnsureNICDevice(string, incus.NICDevice) error { return nil }
func (b *nativeBirthBackend) SetOwnedACL(_ string, acl, device, prefix string) error {
	if b.failAttach {
		return errors.New("fixture: ACL attachment denied")
	}
	b.attached = acl
	return nil
}
func (b *nativeBirthBackend) SetDeviceConfig(_, _ string, keys map[string]string) error {
	b.nicKeys = keys
	return nil
}
func (b *nativeBirthBackend) StartContainer(string) error {
	if b.acl == nil || b.attached != tenantguard.ACLName("team-a") || b.nicKeys["security.acls.default.ingress.action"] != "drop" || b.createdConfig.ExtraConfig[incus.TenantLabelKey] != "team-a" {
		return fmt.Errorf("Start reached before native membership and required default-drop NIC ACL")
	}
	b.started = true
	return nil
}
func (b *nativeBirthBackend) DeleteContainer(string) error { b.deleteCalls++; return b.cleanupErr }
func TestNativeTenantManagerWithRealReconcilerBeforeFirstStart(t *testing.T) {
	for _, kind := range []string{"success", "attachment failure", "cleanup failure"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			b := &nativeBirthBackend{guardBackend: &guardBackend{stagesBackend: &stagesBackend{}}, failAttach: kind != "success"}
			cleanupErr := errors.New("fixture: delete denied")
			if kind == "cleanup failure" {
				b.cleanupErr = cleanupErr
			}
			m := NewWithBackend(b)
			m.SetNICGuard(tenantguard.NewReconciler(b, tenantguard.Config{Mode: nicguard.ModeEnforce, Bridge: "incusbr0", BridgeCIDR: "192.0.2.1/24"}))
			opts := stagesOpts()
			opts.NetworkTenant = "team-a"
			opts.AutoStart = true
			_, err := m.Create(opts)
			if kind == "success" {
				if err != nil || !b.started || b.attached != tenantguard.ACLName("team-a") || b.createdConfig.AutoStart {
					t.Fatalf("birth lifecycle %v %+v", err, b)
				}
			} else {
				if !errors.Is(err, ErrNICGuard) || b.started || b.createdConfig.AutoStart || b.deleteCalls != 1 {
					t.Fatalf("unsafe failure: %v", err)
				}
				if kind == "cleanup failure" && !errors.Is(err, cleanupErr) {
					t.Fatalf("cleanup cause lost: %v", err)
				}
			}
		})
	}
}
