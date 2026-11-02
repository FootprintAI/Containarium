package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeTenantCLIRequiresDaemonBeforeLocalForce(t *testing.T) {
	oldServer, oldTenant := serverAddr, createNetworkTenant
	t.Cleanup(func() { serverAddr, createNetworkTenant = oldServer, oldTenant })
	serverAddr = ""
	createNetworkTenant = "team-a"
	if err := runCreate(createCmd, []string{"workload"}); err == nil || !strings.Contains(err.Error(), "requires a daemon") {
		t.Fatal(err)
	}
	if createCmd.Flags().Lookup("network-tenant") == nil {
		t.Fatal("CLI flag missing")
	}
}
func TestNativeTenantCLICapabilityQuery(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/network-tenants/capabilities" || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("wrong request")
		}
		_, _ = io.WriteString(w, `{"contract":"native-network-tenant/v1","backendScope":"local-lxc","nativeMembershipRead":true,"sharedTenantCreate":true,"atomicTenantAccess":false,"networkPolicyWrite":false}`)
	}))
	defer fixture.Close()
	oldServer, oldHTTP, oldToken := serverAddr, httpMode, authToken
	t.Cleanup(func() { serverAddr, httpMode, authToken = oldServer, oldHTTP, oldToken })
	serverAddr, httpMode, authToken = fixture.URL, true, "fixture-token"
	var out bytes.Buffer
	cmd := networkGuardStatusCmd
	oldWriter := cmd.OutOrStdout()
	cmd.SetOut(&out)
	t.Cleanup(func() { cmd.SetOut(oldWriter) })
	if err := runNetworkTenantCapabilities(cmd); err != nil {
		t.Fatal(err)
	}
	var value struct {
		AtomicTenantAccess *bool `json:"atomicTenantAccess"`
		SharedTenantCreate bool  `json:"sharedTenantCreate"`
	}
	if err := json.Unmarshal(out.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value.AtomicTenantAccess == nil || *value.AtomicTenantAccess || !value.SharedTenantCreate {
		t.Fatal(out.String())
	}
}
