package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// get_system_info carries SystemInfo.storage_pools through grpc-gateway JSON
// and prints each pool with its level (#2823).
func TestHandleGetSystemInfo_StoragePools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"hostname":"h1","storagePools":[
			{"pool":"p1","driver":"STORAGE_DRIVER_ZFS","usedBytes":"96","totalBytes":"100","level":"STORAGE_POOL_CAPACITY_LEVEL_CRITICAL"},
			{"pool":"p2","driver":"STORAGE_DRIVER_DIR","usedBytes":"10","totalBytes":"100","level":"STORAGE_POOL_CAPACITY_LEVEL_OK"}]}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resp, err := client.GetSystemInfo()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Info.StoragePools) != 2 || resp.Info.StoragePools[0].UsedBytes != 96 || resp.Info.StoragePools[0].TotalBytes != 100 {
		t.Fatalf("storage pools did not round-trip: %+v", resp.Info.StoragePools)
	}
	out, err := handleGetSystemInfo(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"Storage pools:", "p1: 96.0% full (critical)", "p2: 10.0% full (ok)"} {
		if !strings.Contains(out, needle) {
			t.Errorf("output lacks %q:\n%s", needle, out)
		}
	}
}
