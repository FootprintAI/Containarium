package mcp

import "testing"

// #2733 (slice B of #2263): the bridge_dns_status tool is removed together
// with its CLI counterpart and the RPC both wrapped.
func TestBridgeDNSStatusToolRemoved(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	if len(srv.tools) == 0 {
		t.Fatal("no tools registered; test harness broken")
	}
	for _, tool := range srv.tools {
		if tool.Name == "bridge_dns_status" {
			t.Error("bridge_dns_status is still registered")
		}
	}
	if _, ok := toolScopeAssignments()["bridge_dns_status"]; ok {
		t.Error("bridge_dns_status still has a scope assignment")
	}
}
