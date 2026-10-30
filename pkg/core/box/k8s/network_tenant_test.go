package k8s

import (
	"context"
	"github.com/footprintai/containarium/pkg/core/box"
	"strings"
	"testing"
)

func TestNativeTenantRejectedBeforeKubernetesAllocation(t *testing.T) {
	b := &Backend{} // Any API access would panic: no client is configured.
	_, err := b.Create(context.Background(), box.BoxSpec{NetworkTenant: "team-a"})
	if err == nil || !strings.Contains(err.Error(), "local Linux LXC") {
		t.Fatal(err)
	}
}
