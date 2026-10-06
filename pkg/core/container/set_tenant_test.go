package container

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

type tenantBackend struct {
	incus.Backend
	name, key, value string
}

func (b *tenantBackend) UpdateContainerConfig(name, key, value string) error {
	b.name, b.key, b.value = name, key, value
	return nil
}

// SetTenant writes the explicit-owner config key on the named container —
// by container name, since the owner is exactly what no longer matches
// the name (#2199).
func TestSetTenant(t *testing.T) {
	be := &tenantBackend{}
	m := NewWithBackend(be)

	if err := m.SetTenant("anon-1a2b3c4d-container", "qa-claim"); err != nil {
		t.Fatal(err)
	}
	if be.name != "anon-1a2b3c4d-container" || be.key != incus.TenantLabelKey || be.value != "qa-claim" {
		t.Errorf("wrote %s %s=%s", be.name, be.key, be.value)
	}
	if err := m.SetTenant("anon-1a2b3c4d-container", ""); err == nil {
		t.Error("empty tenant must be refused")
	}
}
