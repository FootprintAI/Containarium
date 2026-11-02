package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Numeric enums and int64s are valid ProtoJSON too; unknown fields at any
// level must not prevent an older client from reading a newer daemon.
func TestGetSystemInfoAcceptsProtoJSON(t *testing.T) {
	for _, mode := range []string{`"CPU_ADMISSION_MODE_ENFORCING"`, `3`} {
		t.Run(mode, func(t *testing.T) {
			_, c := newBodyRecorder(t, fmt.Sprintf(`{
				"futureResponseField":true,
				"info":{
					"totalMemoryBytes":34359738368,"availableMemoryBytes":17179869184,
					"totalCpus":12,"committedCpuCores":4.5,"coreCommittedCpuCores":2.25,
					"cpuAdmissionMode":%s,"cpuOvercommitFactor":2.5,
					"futureSystemField":{"value":"new"},
					"storagePools":[{"pool":"p1","driver":"STORAGE_DRIVER_ZFS",
						"usedBytes":"96","totalBytes":"100","futurePoolField":true}]
				}}`, mode))
			info, err := c.GetSystemInfo()
			if err != nil {
				t.Fatalf("GetSystemInfo: %v", err)
			}
			if info.CPUBudget == nil || info.CPUBudget.AdmissionMode != incus.CPUAdmissionEnforcing {
				t.Errorf("CPU budget not decoded: %+v", info.CPUBudget)
			}
			if len(info.StoragePools) != 1 || info.StoragePools[0].UsedBytes != 96 || info.StoragePools[0].TotalBytes != 100 {
				t.Errorf("storage pools not decoded: %+v", info.StoragePools)
			}
		})
	}
}

func TestSystemInfoInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"missing info", 200, `{}`, "no system info returned"},
		{"null info", 200, `{"info":null}`, "no system info returned"},
		{"malformed JSON", 200, `{"info":`, "failed to parse response"},
		{"invalid int64", 200, `{"info":{"totalMemoryBytes":"invalid"}}`, "failed to parse response"},
		{"HTTP error", 403, `{"error":"scope required: containers:read","code":403}`, "scope required: containers:read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c, err := NewHTTPClient(srv.URL, "tok")
			if err != nil {
				t.Fatal(err)
			}
			_, infoErr := c.GetSystemInfo()
			_, keyErr := c.ManagedBackupKeyConfigured()
			for name, err := range map[string]error{"info": infoErr, "managed key": keyErr} {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("%s error = %v, want %q", name, err, tc.want)
				}
			}
		})
	}
}
