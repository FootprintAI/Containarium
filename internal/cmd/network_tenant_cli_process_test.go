package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNativeTenantCLIProcessHelper(t *testing.T) {
	mode := os.Getenv("NATIVE_TENANT_CLI_FIXTURE")
	if mode == "" {
		return
	}
	rootCmd.SetArgs([]string{"create", "workload", "--network-tenant", "team-a", "--tenant", "default", "--no-ssh-key", "--force", "--server", os.Getenv("NATIVE_TENANT_CLI_URL"), "--http", "--token", "fixture-token"})
	err := Execute()
	if mode == "supported" && err != nil {
		t.Fatal(err)
	}
	if mode == "unsupported" && err == nil {
		t.Fatal("old Provider force-create unexpectedly succeeded")
	}
}
func TestNativeTenantCLIFlagAndForcePreflight(t *testing.T) {
	for _, supported := range []bool{true, false} {
		t.Run(map[bool]string{true: "supported", false: "unsupported"}[supported], func(t *testing.T) {
			creates, deletes, preflights := 0, 0, 0
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("authentication missing")
				}
				if r.URL.Path == "/v1/network-tenants/capabilities" {
					if !supported {
						http.NotFound(w, r)
						return
					}
					_, _ = w.Write([]byte(`{"contract":"boxweave.tenant-network/v1","backendScope":"local-lxc","nativeMembershipRead":true,"sharedTenantCreate":true}`))
					return
				}
				if r.URL.Path == "/v1/containers/workload" {
					if r.Method == "DELETE" {
						if preflights != 1 {
							t.Error("delete preceded exact preflight")
						}
						deletes++
					}
					_, _ = w.Write([]byte(`{"container":{"name":"workload-container","username":"workload","state":"CONTAINER_STATE_RUNNING"}}`))
					return
				}
				if r.Method != "POST" || r.URL.Path != "/v1/containers" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				var req struct {
					NetworkTenant string `json:"networkTenant"`
					TenantID      string `json:"tenantId"`
					DryRun        bool   `json:"dryRun"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
				}
				if req.NetworkTenant != "team-a" || req.TenantID != "default" {
					t.Error("CLI flag or encryption field lost")
				}
				if req.DryRun {
					preflights++
					_, _ = w.Write([]byte(`{"dryRun":true}`))
					return
				}
				creates++
				_, _ = w.Write([]byte(`{"container":{"name":"workload-container","state":"CONTAINER_STATE_RUNNING","networkTenant":"observed-team","networkTenantSource":"NETWORK_TENANT_SOURCE_NATIVE"}}`))
			}))
			defer fixture.Close()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeTenantCLIProcessHelper$")
			mode := "unsupported"
			if supported {
				mode = "supported"
			}
			cmd.Env = append(os.Environ(), "NATIVE_TENANT_CLI_FIXTURE="+mode, "NATIVE_TENANT_CLI_URL="+fixture.URL, "HOME="+t.TempDir())
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("CLI subprocess: %v %s", err, out)
			}
			if supported {
				if creates != 1 || deletes != 1 || preflights != 1 {
					t.Fatalf("wrong operation counts: %d %d %d", creates, deletes, preflights)
				}
			} else if creates != 0 || deletes != 0 || preflights != 0 {
				t.Fatal("old Provider received destructive write")
			}
		})
	}
}
