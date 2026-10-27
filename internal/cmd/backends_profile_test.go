package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestBackendsProfileDaemonJSON exercises the actual protobuf JSON wire shape:
// operators must be able to read capacities and benchmark scores in text mode.
func TestBackendsProfileDaemonJSON(t *testing.T) {
	profile := &pb.CapabilityProfile{
		CpuCores: 8, TotalMemoryBytes: 16 << 30, TotalDiskBytes: 128 << 30,
		MeasuredClass: "cpu-small", ClassConsistent: true,
		Benchmark: &pb.CapabilityBenchmark{CpuOpsPerSec: 123456, MemBytesPerSec: 2 << 30, DurationMs: 300},
	}
	for _, get := range []bool{false, true} {
		method := http.MethodPost
		if get {
			method = http.MethodGet
		}
		for _, mode := range []string{"text", "json", "unprofiled"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				p := profile
				if mode == "unprofiled" {
					p = nil
				}
				var response proto.Message = &pb.ProfileBackendResponse{BackendId: "peer-test", Profile: p}
				if get {
					response = &pb.GetCapabilityProfileResponse{BackendId: "peer-test", Profile: p}
				}
				body, err := protojson.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != method || r.URL.Path != "/v1/capabilities/profile" {
						t.Errorf("request = %s %s, want %s /v1/capabilities/profile", r.Method, r.URL.Path, method)
					}
					if get && r.URL.Query().Get("backend_id") != "peer-test" {
						t.Error("GET must select the requested backend")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(body)
				}))
				defer srv.Close()
				oldServer, oldToken := serverAddr, authToken
				oldGet, oldFormat, oldSkip := profileBackendGet, profileBackendFormat, profileBackendSkipGPU
				t.Cleanup(func() {
					serverAddr, authToken = oldServer, oldToken
					profileBackendGet, profileBackendFormat, profileBackendSkipGPU = oldGet, oldFormat, oldSkip
				})
				serverAddr, authToken = srv.URL, ""
				profileBackendGet, profileBackendFormat, profileBackendSkipGPU = get, mode, true
				var out bytes.Buffer
				cmd := &cobra.Command{}
				cmd.SetOut(&out)
				if err := runBackendsProfile(cmd, []string{"peer-test"}); err != nil {
					t.Fatalf("read daemon profile: %v", err)
				}
				if mode == "json" {
					if out.String() != string(body)+"\n" {
						t.Fatalf("JSON output changed: %s", out.String())
					}
					return
				}
				if mode == "unprofiled" {
					if !strings.Contains(out.String(), "no capability profile recorded for peer-test yet") {
						t.Fatalf("missing profile must remain explicit: %s", out.String())
					}
					return
				}
				for _, want := range []string{"Capability profile for peer-test:", humanBytes(16 << 30), humanBytes(128 << 30), "CPU 123456 ops/s", humanBytes(2<<30) + "/s (300ms)", "cpu-small", "consistent"} {
					if !strings.Contains(out.String(), want) {
						t.Errorf("output missing %q: %s", want, out.String())
					}
				}
			})
		}
	}
}
