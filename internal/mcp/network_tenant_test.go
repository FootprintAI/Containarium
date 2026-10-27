package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeTenantMCPCreateAndReadback(t *testing.T) {
	calls := 0
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing authenticated request")
		}
		switch r.URL.Path {
		case "/v1/network-tenants/capabilities":
			_, _ = w.Write([]byte(`{"contract":"native-network-tenant/v1","backendScope":"local-lxc","nativeMembershipRead":true,"sharedTenantCreate":true,"atomicTenantAccess":false,"networkPolicyWrite":false}`))
		case "/v1/containers":
			calls++
			var req CreateContainerRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.NetworkTenant != "team-a" || req.TenantID != "default" {
				t.Error("MCP lost native Tenant or conflated encryption")
			}
			_, _ = w.Write([]byte(`{"container":{"name":"workload-container","username":"workload","networkTenant":"observed-team","networkTenantSource":"NETWORK_TENANT_SOURCE_NATIVE"}}`))
		case "/v1/containers/workload":
			_, _ = w.Write([]byte(`{"container":{"name":"workload-container","networkTenant":"observed-team","networkTenantSource":"NETWORK_TENANT_SOURCE_NATIVE"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer fixture.Close()
	c := NewClient(fixture.URL, "fixture-token")
	args := map[string]interface{}{"username": "workload", "network_tenant": "team-a", "tenant_id": "default", "ssh_keys": []interface{}{"ssh-ed25519 fixture-public-only"}}
	if _, err := handleCreateContainer(c, args); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	data, err := handleGetContainer(c, map[string]interface{}{"username": "workload"})
	if err != nil || !strings.Contains(data, "observed-team") || !strings.Contains(data, "NETWORK_TENANT_SOURCE_NATIVE") {
		t.Fatalf("query %s %v", data, err)
	}
	args["network_tenant"] = 123
	if _, err := handleCreateContainer(c, args); err == nil || calls != 1 {
		t.Fatal("non-string native identity silently ignored")
	}
}
func TestNativeTenantMCPCapabilityToolAndScope(t *testing.T) {
	s := &Server{}
	s.registerTools()
	var found bool
	for _, tool := range s.tools {
		if tool.Name == "network_tenant_capabilities" {
			found = true
			if tool.RequiredScope != "containers:read" {
				t.Fatal(tool.RequiredScope)
			}
		}
		if tool.Name == "create_container" {
			properties := tool.InputSchema["properties"].(map[string]interface{})
			if _, ok := properties["network_tenant"]; !ok {
				t.Fatal("MCP native field missing")
			}
		}
	}
	if !found {
		t.Fatal("capability tool missing")
	}
}
