package client

import (
	"encoding/json"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeTenantCreateRequestIndependentEncryptionAndLegacyFields(t *testing.T) {
	req := NewCreateContainerRequest("workload", "image", "1", "1GB", "1GB", nil, false, "", nil, 0, 0, false, "", "", GitSourceOpts{}, 0, 0, false, 0, "", EncryptionOpts{TenantID: "default"}, "", "", "", nil, "team-a")
	if req.NetworkTenant != "team-a" || req.TenantId != "default" || req.DryRun {
		t.Fatal(req)
	}
	if req.ProtoReflect().Descriptor().Fields().ByName("dry_run").Number() != 29 || req.ProtoReflect().Descriptor().Fields().ByName("network_tenant").Number() != 30 {
		t.Fatal("existing field reused")
	}
	c := &pb.Container{}
	if c.ProtoReflect().Descriptor().Fields().ByName("tool_access").Number() != 30 || c.ProtoReflect().Descriptor().Fields().ByName("network_tenant").Number() != 31 {
		t.Fatal("existing Container field reused")
	}
}
func TestNativeTenantHTTPCreateAndOldProviderNoWrite(t *testing.T) {
	for _, supported := range []bool{true, false} {
		creates := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/network-tenants/capabilities" {
				if !supported {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write([]byte(`{"contract":"boxweave.tenant-network/v1","backendScope":"local-lxc","nativeMembershipRead":true,"sharedTenantCreate":true,"atomicTenantAccess":false,"networkPolicyWrite":false}`))
				return
			}
			if r.URL.Path != "/v1/containers" || r.Method != "POST" {
				t.Errorf("unexpected request %s", r.URL.Path)
				http.NotFound(w, r)
				return
			}
			creates++
			var body createContainerRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.NetworkTenant != "team-a" || body.TenantID != "default" {
				t.Error("network/encryption drift")
			}
			_, _ = w.Write([]byte(`{"container":{"name":"workload-container","networkTenant":"observed-team","networkTenantSource":"NETWORK_TENANT_SOURCE_NATIVE"}}`))
		}))
		c, err := NewHTTPClient(server.URL, "fixture-not-a-secret")
		if err != nil {
			t.Fatal(err)
		}
		out, err := c.CreateContainer("workload", "image", "1", "1GB", "1GB", nil, false, "", nil, 0, 0, false, "", "", GitSourceOpts{}, 0, 0, false, 0, "", EncryptionOpts{TenantID: "default"}, "", "", "", nil, "team-a")
		_ = c.Close()
		server.Close()
		if supported {
			if err != nil || out.Tenant != "observed-team" || out.NetworkTenantSource != incus.NetworkTenantSourceNative || creates != 1 {
				t.Fatalf("readback: %+v %v creates=%d", out, err, creates)
			}
		} else if err == nil || creates != 0 {
			t.Fatal("older Provider received unsafe create")
		}
	}
}
