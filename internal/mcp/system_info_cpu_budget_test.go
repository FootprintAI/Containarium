package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleGetSystemInfo_CPUBudget: the MCP get_system_info wrapper carries
// the SystemInfo CPU budget fields through unchanged and prints the advisory
// warning the daemon would (#2284) — a thin wrapper over the proto contract.
func TestHandleGetSystemInfo_CPUBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/system/info" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		// Shape as grpc-gateway emits it: camelCase, enum by name,
		// doubles as numbers.
		_, _ = w.Write([]byte(`{"info":{"hostname":"h1","os":"Ubuntu","kernelVersion":"6.8","incusVersion":"6.0",
			"containersRunning":70,"containersStopped":0,"containersTotal":70,
			"totalCpus":8,"committedCpuCores":199,"coreCommittedCpuCores":8,
			"cpuAdmissionMode":"CPU_ADMISSION_MODE_ADVISORY","cpuOvercommitFactor":4}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resp, err := client.GetSystemInfo()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Info.TotalCpus != 8 || resp.Info.CommittedCpuCores != 199 || resp.Info.CoreCommittedCpuCores != 8 ||
		resp.Info.CpuAdmissionMode != "CPU_ADMISSION_MODE_ADVISORY" || resp.Info.CpuOvercommitFactor != 4 {
		t.Fatalf("budget fields did not round-trip: %+v", resp.Info)
	}

	out, err := handleGetSystemInfo(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"CPU budget:",
		"Physical CPUs: 8",
		"Tenant committed: 199.00 cores (24.88×)",
		"Core committed: 8.00 cores",
		"Admission gate: advisory, factor 4.00× (ceiling 32.00 cores)",
		"WARNING",
		"not enforcing",
	} {
		if !strings.Contains(out, needle) {
			t.Errorf("output lacks %q:\n%s", needle, out)
		}
	}
}

// An older daemon that does not send the fields must render as "not
// reported", never as a zero-core host with a disabled gate.
func TestHandleGetSystemInfo_CPUBudgetAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(GetSystemInfoResponse{Info: SystemInfo{Hostname: "h1", IncusVersion: "6.0"}})
	}))
	defer server.Close()

	out, err := handleGetSystemInfo(NewClient(server.URL, "test-token"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "CPU budget: not reported") {
		t.Errorf("absent budget must say not reported:\n%s", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("absent budget must not warn:\n%s", out)
	}
}
