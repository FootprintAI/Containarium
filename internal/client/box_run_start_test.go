package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A synthetic value, long and odd enough that finding it in an error or a
// request is never a coincidence.
const testRunToken = "synthetic-run-token-7c1d.not-a-credential"

// boxRunStartCase is one StartBoxRun scenario, run against both transports.
type boxRunStartCase struct {
	name         string
	capabilities []string
	token        string
	workdir      string
	// wantRefused: the client refuses before the daemon's StartBoxRun is
	// called, with wantRefusal (BoxRunTokenUnsupportedMessage when empty).
	wantRefused bool
	wantRefusal string
	// wantInfoCalls is how often the daemon's capabilities are read.
	wantInfoCalls int
}

func boxRunStartCases() []boxRunStartCase {
	return []boxRunStartCase{
		{
			name:          "a token reaches a daemon that advertises box_run_token",
			capabilities:  []string{"box_run_name", BoxRunTokenCapability},
			token:         testRunToken,
			wantInfoCalls: 1,
		},
		{
			name:          "a token is refused for a daemon without box_run_token",
			capabilities:  []string{"box_run_name", "box_run_model"},
			token:         testRunToken,
			wantRefused:   true,
			wantInfoCalls: 1,
		},
		{
			name:          "a token is refused for a daemon that reports no capabilities",
			token:         testRunToken,
			wantRefused:   true,
			wantInfoCalls: 1,
		},
		{
			name:         "a run without a token needs no capability and no capability read",
			capabilities: []string{"box_run_name"},
		},
		// #3613: an older daemon would drop workdir over gRPC and start the run
		// in the home, so a workdir goes only to one that advertises it.
		{
			name:          "a workdir reaches a daemon that advertises box_run_workdir",
			capabilities:  []string{"box_run_name", BoxRunWorkdirCapability},
			workdir:       "project",
			wantInfoCalls: 1,
		},
		{
			name:          "a workdir is refused for a daemon without box_run_workdir",
			capabilities:  []string{"box_run_name", BoxRunTokenCapability},
			workdir:       "project",
			wantRefused:   true,
			wantRefusal:   BoxRunWorkdirUnsupportedMessage,
			wantInfoCalls: 1,
		},
		{
			name:          "a token and a workdir read the capabilities once",
			capabilities:  []string{BoxRunTokenCapability, BoxRunWorkdirCapability},
			token:         testRunToken,
			workdir:       "project",
			wantInfoCalls: 1,
		},
		{
			name:          "a token with a workdir is refused for a daemon with box_run_token only",
			capabilities:  []string{BoxRunTokenCapability},
			token:         testRunToken,
			workdir:       "project",
			wantRefused:   true,
			wantRefusal:   BoxRunWorkdirUnsupportedMessage,
			wantInfoCalls: 1,
		},
	}
}

// boxRunStartRecord is what a fake daemon saw.
type boxRunStartRecord struct {
	mu        sync.Mutex
	infoCalls int
	starts    []*pb.StartBoxRunRequest
}

func (r *boxRunStartRecord) check(t *testing.T, tc boxRunStartCase, resp *pb.StartBoxRunResponse, err error) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.infoCalls != tc.wantInfoCalls {
		t.Errorf("capability reads = %d, want %d", r.infoCalls, tc.wantInfoCalls)
	}
	if tc.wantRefused {
		if err == nil {
			t.Fatal("StartBoxRun succeeded, want the unsupported refusal")
		}
		want := tc.wantRefusal
		if want == "" {
			want = BoxRunTokenUnsupportedMessage
		}
		if err.Error() != want {
			t.Errorf("err = %q, want %q", err, want)
		}
		if tc.token != "" && strings.Contains(err.Error(), tc.token) {
			t.Errorf("the refusal carries the token: %q", err)
		}
		if len(r.starts) != 0 {
			t.Fatalf("the daemon's StartBoxRun was called %d time(s) after a refusal", len(r.starts))
		}
		return
	}
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if len(r.starts) != 1 {
		t.Fatalf("the daemon's StartBoxRun was called %d time(s), want 1", len(r.starts))
	}
	got := r.starts[0]
	if got.GetRunToken() != tc.token {
		t.Errorf("run_token at the daemon = %q, want %q", got.GetRunToken(), tc.token)
	}
	if got.GetWorkdir() != tc.workdir {
		t.Errorf("workdir at the daemon = %q, want %q", got.GetWorkdir(), tc.workdir)
	}
	if got.GetUsername() != "alice" || got.GetPrompt() != "fix the bug" || got.GetRunName() != "issue-1" || got.GetModel() != "some-model" {
		t.Errorf("request at the daemon = %v", got)
	}
	if resp.GetRun().GetRunName() != "issue-1" || resp.GetRun().GetLogPath() != "/home/alice/issue-1.log" {
		t.Errorf("response = %v", resp)
	}
}

func boxRunStartRequest(token string) *pb.StartBoxRunRequest {
	return &pb.StartBoxRunRequest{Username: "alice", Prompt: "fix the bug", RunName: "issue-1", Model: "some-model", RunToken: token}
}

// request is the case's request: its token and workdir.
func (tc boxRunStartCase) request() *pb.StartBoxRunRequest {
	req := boxRunStartRequest(tc.token)
	req.Workdir = tc.workdir
	return req
}

type boxRunStartGRPCFixture struct {
	pb.UnimplementedContainerServiceServer
	capabilities []string
	rec          *boxRunStartRecord
	startErr     error
}

func (f *boxRunStartGRPCFixture) GetSystemInfo(context.Context, *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	f.rec.infoCalls++
	return &pb.GetSystemInfoResponse{Info: &pb.SystemInfo{Capabilities: f.capabilities}}, nil
}

func (f *boxRunStartGRPCFixture) StartBoxRun(_ context.Context, req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	f.rec.starts = append(f.rec.starts, req)
	if f.startErr != nil {
		return nil, f.startErr
	}
	return &pb.StartBoxRunResponse{Run: &pb.BoxRun{RunName: req.GetRunName(), LogPath: "/home/alice/issue-1.log"}}, nil
}

func newBoxRunStartGRPCClient(t *testing.T, fixture pb.ContainerServiceServer) *GRPCClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterContainerServiceServer(srv, fixture)
	go func() { _ = srv.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///fixture",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	c := &GRPCClient{conn: conn, client: pb.NewContainerServiceClient(conn)}
	t.Cleanup(func() {
		_ = c.Close()
		srv.Stop()
	})
	return c
}

func TestGRPCStartBoxRun(t *testing.T) {
	for _, tc := range boxRunStartCases() {
		t.Run(tc.name, func(t *testing.T) {
			rec := &boxRunStartRecord{}
			c := newBoxRunStartGRPCClient(t, &boxRunStartGRPCFixture{capabilities: tc.capabilities, rec: rec})
			resp, err := c.StartBoxRun(tc.request())
			rec.check(t, tc, resp, err)
		})
	}
}

// The daemon's own refusal keeps its gRPC code, so a caller can tell a
// FAILED_PRECONDITION from an older daemon's Unimplemented.
func TestGRPCStartBoxRun_DaemonErrorKeepsItsCode(t *testing.T) {
	rec := &boxRunStartRecord{}
	c := newBoxRunStartGRPCClient(t, &boxRunStartGRPCFixture{
		rec:      rec,
		startErr: status.Error(codes.FailedPrecondition, "run \"issue-1\" is still running"),
	})
	_, err := c.StartBoxRun(boxRunStartRequest(""))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("err = %v, want the daemon's FAILED_PRECONDITION", err)
	}
}

// A daemon whose capabilities cannot be read is not sent a token.
func TestGRPCStartBoxRun_CapabilityReadFailureRefusesAToken(t *testing.T) {
	rec := &boxRunStartRecord{}
	// No GetSystemInfo on this fixture: the read is Unimplemented.
	c := newBoxRunStartGRPCClient(t, &boxRunStartNoInfoFixture{rec: rec})
	_, err := c.StartBoxRun(boxRunStartRequest(testRunToken))
	if err == nil || !strings.Contains(err.Error(), BoxRunTokenCapability) {
		t.Fatalf("err = %v, want a capability-check failure naming %s", err, BoxRunTokenCapability)
	}
	if strings.Contains(err.Error(), testRunToken) {
		t.Errorf("the error carries the token: %q", err)
	}
	if len(rec.starts) != 0 {
		t.Fatalf("the daemon's StartBoxRun was called %d time(s)", len(rec.starts))
	}
}

// A daemon whose capabilities cannot be read is not sent a workdir either: it
// might be one that drops the field (#3613).
func TestGRPCStartBoxRun_CapabilityReadFailureRefusesAWorkdir(t *testing.T) {
	rec := &boxRunStartRecord{}
	c := newBoxRunStartGRPCClient(t, &boxRunStartNoInfoFixture{rec: rec})
	req := boxRunStartRequest("")
	req.Workdir = "project"
	_, err := c.StartBoxRun(req)
	if err == nil || !strings.Contains(err.Error(), BoxRunWorkdirCapability) {
		t.Fatalf("err = %v, want a capability-check failure naming %s", err, BoxRunWorkdirCapability)
	}
	if len(rec.starts) != 0 {
		t.Fatalf("the daemon's StartBoxRun was called %d time(s)", len(rec.starts))
	}
}

type boxRunStartNoInfoFixture struct {
	pb.UnimplementedContainerServiceServer
	rec *boxRunStartRecord
}

func (f *boxRunStartNoInfoFixture) StartBoxRun(_ context.Context, req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	f.rec.starts = append(f.rec.starts, req)
	return &pb.StartBoxRunResponse{}, nil
}

// newBoxRunStartHTTPServer is the REST fake: GET /v1/system/info and
// POST /v1/containers/alice/code-runs, anything else a test failure.
func newBoxRunStartHTTPServer(t *testing.T, capabilities []string, rec *boxRunStartRecord) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/system/info":
			rec.infoCalls++
			b, err := protojson.Marshal(&pb.GetSystemInfoResponse{Info: &pb.SystemInfo{Capabilities: capabilities}})
			if err != nil {
				t.Errorf("encode system info: %v", err)
			}
			_, _ = w.Write(b)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/containers/alice/code-runs":
			body, _ := io.ReadAll(r.Body)
			req := &pb.StartBoxRunRequest{}
			if err := protojson.Unmarshal(body, req); err != nil {
				t.Errorf("the request body is not a StartBoxRunRequest: %v (%s)", err, body)
			}
			rec.starts = append(rec.starts, req)
			// futureField: a newer daemon's extra field must not break decoding.
			_, _ = w.Write([]byte(`{"run":{"runName":"` + req.GetRunName() + `","logPath":"/home/alice/issue-1.log","futureField":1},"futureField":true}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPStartBoxRun(t *testing.T) {
	for _, tc := range boxRunStartCases() {
		t.Run(tc.name, func(t *testing.T) {
			rec := &boxRunStartRecord{}
			srv := newBoxRunStartHTTPServer(t, tc.capabilities, rec)
			c, err := NewHTTPClient(srv.URL, "tok")
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.StartBoxRun(tc.request())
			rec.check(t, tc, resp, err)
		})
	}
}

func TestHTTPStartBoxRun_Errors(t *testing.T) {
	t.Run("an old daemon without the route is Unimplemented", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		if _, err := c.StartBoxRun(boxRunStartRequest("")); status.Code(err) != codes.Unimplemented {
			t.Fatalf("err = %v, want Unimplemented", err)
		}
	})
	t.Run("a gateway NOT_FOUND (no such box) is not Unimplemented", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"no box for \"alice\""}`))
		}))
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		_, err := c.StartBoxRun(boxRunStartRequest(""))
		if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "no box for") {
			t.Fatalf("err = %v, want the daemon's NOT_FOUND", err)
		}
	})
	t.Run("the daemon's refusal keeps its code and message", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":9,"message":"run \"issue-1\" is still running"}`))
		}))
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		_, err := c.StartBoxRun(boxRunStartRequest(""))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still running") {
			t.Fatalf("err = %v, want the daemon's FAILED_PRECONDITION", err)
		}
	})
	t.Run("a daemon whose capabilities cannot be read is not sent a token", func(t *testing.T) {
		var starts int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				starts++
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		_, err := c.StartBoxRun(boxRunStartRequest(testRunToken))
		if err == nil || !strings.Contains(err.Error(), BoxRunTokenCapability) {
			t.Fatalf("err = %v, want a capability-check failure naming %s", err, BoxRunTokenCapability)
		}
		if strings.Contains(err.Error(), testRunToken) {
			t.Errorf("the error carries the token: %q", err)
		}
		if starts != 0 {
			t.Fatalf("StartBoxRun was posted %d time(s)", starts)
		}
	})
}

// The message is what an operator reads; it names the field and the capability.
func TestBoxRunTokenUnsupportedMessage(t *testing.T) {
	for _, want := range []string{"run_token", BoxRunTokenCapability, "upgrade"} {
		if !strings.Contains(BoxRunTokenUnsupportedMessage, want) {
			t.Errorf("BoxRunTokenUnsupportedMessage = %q, want it to name %q", BoxRunTokenUnsupportedMessage, want)
		}
	}
}

func TestBoxRunWorkdirUnsupportedMessage(t *testing.T) {
	for _, want := range []string{"workdir", BoxRunWorkdirCapability, "upgrade"} {
		if !strings.Contains(BoxRunWorkdirUnsupportedMessage, want) {
			t.Errorf("BoxRunWorkdirUnsupportedMessage = %q, want it to name %q", BoxRunWorkdirUnsupportedMessage, want)
		}
	}
}
