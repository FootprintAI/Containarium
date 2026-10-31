package cmd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
)

// Exercise the HTTP client through the CLI: decoding memory without carrying
// it into the rendered output was the remaining gap after #3252 (#3292).
func TestInfoHTTPMemory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, tc := range []struct {
		name string
		info string
		want string
	}{
		{
			name: "gateway quoted int64s",
			info: `{"incusVersion":"6.0.2","kernelVersion":"6.8.0","os":"Ubuntu 24.04",
				"totalMemoryBytes":"34359738368","availableMemoryBytes":"17179869184"}`,
			want: "Memory:\n  Total:           32.0 GiB\n  Available:       16.0 GiB\n",
		},
		{
			name: "zero available is reported",
			info: `{"totalMemoryBytes":"34359738368","availableMemoryBytes":"0"}`,
			want: "Memory:\n  Total:           32.0 GiB\n  Available:       0.0 GiB\n",
		},
		{
			name: "older daemon without memory",
			info: `{"incusVersion":"6.0.2"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/system/info":
					_, _ = w.Write([]byte(`{"info":` + tc.info + `}`))
				case "/v1/containers":
					_, _ = w.Write([]byte(`{"containers":[]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			oldServer, oldHTTP, oldToken := serverAddr, httpMode, authToken
			serverAddr, httpMode, authToken = srv.URL, true, "test-token"
			t.Cleanup(func() { serverAddr, httpMode, authToken = oldServer, oldHTTP, oldToken })
			var err error
			out := captureStdout(t, func() { err = runInfo(infoCmd, nil) })
			if err != nil {
				t.Fatalf("info: %v", err)
			}
			if tc.want == "" {
				if strings.Contains(out, "Memory:") {
					t.Fatalf("unreported memory must not look like zero memory:\n%s", out)
				}
			} else if !strings.Contains(out, tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
}

type memoryInfoServer struct {
	pb.UnimplementedContainerServiceServer
}

func (memoryInfoServer) GetSystemInfo(context.Context, *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	return &pb.GetSystemInfoResponse{Info: &pb.SystemInfo{
		TotalMemoryBytes: 32 << 30, AvailableMemoryBytes: 16 << 30,
	}}, nil
}

func (memoryInfoServer) ListContainers(context.Context, *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	return &pb.ListContainersResponse{}, nil
}

func TestInfoGRPCMemory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterContainerServiceServer(srv, memoryInfoServer{})
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	oldServer, oldHTTP, oldInsecure, oldToken := serverAddr, httpMode, insecure, authToken
	serverAddr, httpMode, insecure, authToken = listener.Addr().String(), false, true, ""
	t.Cleanup(func() { serverAddr, httpMode, insecure, authToken = oldServer, oldHTTP, oldInsecure, oldToken })
	out := captureStdout(t, func() { err = runInfo(infoCmd, nil) })
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if want := "Memory:\n  Total:           32.0 GiB\n  Available:       16.0 GiB\n"; !strings.Contains(out, want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
}
