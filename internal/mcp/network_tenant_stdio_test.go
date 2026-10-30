package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNativeTenantMCPStdioHelper(t *testing.T) {
	if os.Getenv("NATIVE_TENANT_MCP_FIXTURE") != "1" {
		return
	}
	srv, err := NewServer(&Config{ServerURL: os.Getenv("NATIVE_TENANT_MCP_URL"), JWTToken: "fixture-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
}
func TestNativeTenantMCPStdioInitializeCreateAndQuery(t *testing.T) {
	creates := 0
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing fixture authentication")
		}
		switch r.URL.Path {
		case "/v1/network-tenants/capabilities":
			_, _ = w.Write([]byte(`{"contract":"native-network-tenant/v1","backendScope":"local-lxc","nativeMembershipRead":true,"sharedTenantCreate":true,"atomicTenantAccess":false,"networkPolicyWrite":false}`))
		case "/v1/containers":
			creates++
			var req CreateContainerRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.NetworkTenant != "team-a" || req.TenantID != "default" {
				t.Error("create contract drift")
			}
			_, _ = w.Write([]byte(`{"container":{"name":"workload-container","username":"workload","networkTenant":"observed-team","networkTenantSource":"NETWORK_TENANT_SOURCE_NATIVE"}}`))
		case "/v1/containers/workload":
			_, _ = w.Write([]byte(`{"container":{"name":"workload-container","networkTenant":"observed-team","networkTenantSource":"NETWORK_TENANT_SOURCE_NATIVE"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer fixture.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNativeTenantMCPStdioHelper$")
	cmd.Env = append(os.Environ(), "NATIVE_TENANT_MCP_FIXTURE=1", "NATIVE_TENANT_MCP_URL="+fixture.URL, "HOME="+t.TempDir())
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	exchange := func(id int, method string, params any) json.RawMessage {
		t.Helper()
		req := struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Method  string `json:"method"`
			Params  any    `json:"params"`
		}{"2.0", id, method, params}
		if err := json.NewEncoder(in).Encode(req); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("MCP closed before %s: %v", method, scanner.Err())
		}
		var reply struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if reply.ID != id || len(reply.Error) > 0 {
			t.Fatalf("MCP %s failed", method)
		}
		var outcome struct {
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(reply.Result, &outcome); err != nil {
			t.Fatal(err)
		}
		if outcome.IsError {
			t.Fatalf("tool result error for %s", method)
		}
		return reply.Result
	}
	result := exchange(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "fixture", "version": "1"}})
	if len(result) == 0 {
		t.Fatal("initialize missing")
	}
	if _, err := in.Write([]byte("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")); err != nil {
		t.Fatal(err)
	}
	tools := exchange(2, "tools/list", map[string]any{})
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(tools, &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range list.Tools {
		if tool.Name == "network_tenant_capabilities" {
			found = true
		}
	}
	if !found {
		t.Fatal("capability missing from actual tools/list")
	}
	exchange(3, "tools/call", map[string]any{"name": "network_tenant_capabilities", "arguments": map[string]any{}})
	exchange(4, "tools/call", map[string]any{"name": "create_container", "arguments": map[string]any{"username": "workload", "network_tenant": "team-a", "tenant_id": "default", "ssh_keys": []string{"ssh-ed25519 fixture-public-only"}}})
	observed := exchange(5, "tools/call", map[string]any{"name": "get_container", "arguments": map[string]string{"username": "workload"}})
	var content struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(observed, &content); err != nil {
		t.Fatal(err)
	}
	if content.IsError || len(content.Content) != 1 || creates != 1 || !strings.Contains(content.Content[0].Text, "observed-team") || !strings.Contains(content.Content[0].Text, "NETWORK_TENANT_SOURCE_NATIVE") {
		t.Fatalf("MCP result failed: creates=%d", creates)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	t.Logf("MCP initialize/initialized, %d tools, authenticated create/query calls passed", len(list.Tools))
}
