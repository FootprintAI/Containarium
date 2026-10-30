package lxc

import (
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"testing"
)

func TestNativeTenantSpecAndProviderReadback(t *testing.T) {
	opts := specToCreateOptions(box.BoxSpec{Ref: box.BoxRef{Tenant: "workload"}, NetworkTenant: "team-a"})
	if opts.Username != "workload" || opts.NetworkTenant != "team-a" {
		t.Fatal(opts)
	}
	info := &incus.ContainerInfo{Name: "workload-container", Username: "workload", Tenant: "team-b", Labels: map[string]string{"tenant": "spoof", incus.CloudOrgIDLabel: "cloud-a"}}
	st := StatusFromInfo(info)
	if st.NetworkTenant != "team-b" || st.NetworkTenantSource != pb.NetworkTenantSource_NETWORK_TENANT_SOURCE_NATIVE || st.Ref.Tenant != "workload" {
		t.Fatal(st)
	}
	info.Tenant = ""
	st = StatusFromInfo(info)
	if st.NetworkTenant != "cloud-a" || st.NetworkTenantSource != pb.NetworkTenantSource_NETWORK_TENANT_SOURCE_CLOUD_ORG_ID {
		t.Fatal(st)
	}
	delete(info.Labels, incus.CloudOrgIDLabel)
	st = StatusFromInfo(info)
	if st.NetworkTenant != "workload" || st.NetworkTenantSource != pb.NetworkTenantSource_NETWORK_TENANT_SOURCE_NAME {
		t.Fatal(st)
	}
	info.InstanceType = "virtual-machine"
	st = StatusFromInfo(info)
	if st.NetworkTenant != "" || st.NetworkTenantSource != pb.NetworkTenantSource_NETWORK_TENANT_SOURCE_UNSPECIFIED {
		t.Fatal(st)
	}
}
