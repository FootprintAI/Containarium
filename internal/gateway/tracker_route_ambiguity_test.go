package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// recordingTracker records which TrackerService RPC the gateway dispatched and
// the path parameters it extracted, as "<Rpc> <param>=<v> ...".
type recordingTracker struct {
	pb.UnimplementedTrackerServiceServer
	mu   sync.Mutex
	last string
}

func (r *recordingTracker) rec(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = fmt.Sprintf(format, a...)
}

func (r *recordingTracker) take() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.last
	r.last = ""
	return s
}

func (r *recordingTracker) GetTrackerConnection(_ context.Context, q *pb.GetTrackerConnectionRequest) (*pb.GetTrackerConnectionResponse, error) {
	r.rec("GetTrackerConnection u=%s name=%s", q.GetUsername(), q.GetName())
	return &pb.GetTrackerConnectionResponse{}, nil
}

func (r *recordingTracker) GetTrackerStatus(_ context.Context, q *pb.GetTrackerStatusRequest) (*pb.GetTrackerStatusResponse, error) {
	r.rec("GetTrackerStatus u=%s name=%s", q.GetUsername(), q.GetName())
	return &pb.GetTrackerStatusResponse{}, nil
}

func (r *recordingTracker) SetTrackerRoute(_ context.Context, q *pb.SetTrackerRouteRequest) (*pb.SetTrackerRouteResponse, error) {
	r.rec("SetTrackerRoute u=%s c=%s scope=%s", q.GetUsername(), q.GetConnection(), q.GetScope())
	return &pb.SetTrackerRouteResponse{}, nil
}

func (r *recordingTracker) ListTrackerRoutes(_ context.Context, q *pb.ListTrackerRoutesRequest) (*pb.ListTrackerRoutesResponse, error) {
	r.rec("ListTrackerRoutes u=%s c=%s", q.GetUsername(), q.GetConnection())
	return &pb.ListTrackerRoutesResponse{}, nil
}

func (r *recordingTracker) DeleteTrackerRoute(_ context.Context, q *pb.DeleteTrackerRouteRequest) (*pb.DeleteTrackerRouteResponse, error) {
	r.rec("DeleteTrackerRoute u=%s c=%s scope=%s", q.GetUsername(), q.GetConnection(), q.GetScope())
	return &pb.DeleteTrackerRouteResponse{}, nil
}

func (r *recordingTracker) DispatchTrackerIssues(_ context.Context, q *pb.DispatchTrackerIssuesRequest) (*pb.DispatchTrackerIssuesResponse, error) {
	r.rec("DispatchTrackerIssues u=%s c=%s", q.GetUsername(), q.GetConnection())
	return &pb.DispatchTrackerIssuesResponse{}, nil
}

func (r *recordingTracker) ListTrackerDispatches(_ context.Context, q *pb.ListTrackerDispatchesRequest) (*pb.ListTrackerDispatchesResponse, error) {
	r.rec("ListTrackerDispatches u=%s c=%s", q.GetUsername(), q.GetConnection())
	return &pb.ListTrackerDispatchesResponse{}, nil
}

func (r *recordingTracker) GetTrackerIssue(_ context.Context, q *pb.GetTrackerIssueRequest) (*pb.GetTrackerIssueResponse, error) {
	r.rec("GetTrackerIssue u=%s c=%s n=%d", q.GetUsername(), q.GetConnection(), q.GetNumber())
	return &pb.GetTrackerIssueResponse{}, nil
}

func (r *recordingTracker) ListTrackerIssues(_ context.Context, q *pb.ListTrackerIssuesRequest) (*pb.ListTrackerIssuesResponse, error) {
	r.rec("ListTrackerIssues u=%s c=%s", q.GetUsername(), q.GetConnection())
	return &pb.ListTrackerIssuesResponse{}, nil
}

func (r *recordingTracker) CreateTrackerIssue(_ context.Context, q *pb.CreateTrackerIssueRequest) (*pb.CreateTrackerIssueResponse, error) {
	r.rec("CreateTrackerIssue u=%s c=%s", q.GetUsername(), q.GetConnection())
	return &pb.CreateTrackerIssueResponse{}, nil
}

func (r *recordingTracker) CommentOnTrackerIssue(_ context.Context, q *pb.CommentOnTrackerIssueRequest) (*pb.CommentOnTrackerIssueResponse, error) {
	r.rec("CommentOnTrackerIssue u=%s c=%s n=%d", q.GetUsername(), q.GetConnection(), q.GetNumber())
	return &pb.CommentOnTrackerIssueResponse{}, nil
}

func (r *recordingTracker) ClaimTrackerIssue(_ context.Context, q *pb.ClaimTrackerIssueRequest) (*pb.ClaimTrackerIssueResponse, error) {
	r.rec("ClaimTrackerIssue u=%s c=%s n=%d", q.GetUsername(), q.GetConnection(), q.GetNumber())
	return &pb.ClaimTrackerIssueResponse{}, nil
}

func (r *recordingTracker) SetTrackerIssueLabels(_ context.Context, q *pb.SetTrackerIssueLabelsRequest) (*pb.SetTrackerIssueLabelsResponse, error) {
	r.rec("SetTrackerIssueLabels u=%s c=%s n=%d", q.GetUsername(), q.GetConnection(), q.GetNumber())
	return &pb.SetTrackerIssueLabelsResponse{}, nil
}

func (r *recordingTracker) GetTrackerChange(_ context.Context, q *pb.GetTrackerChangeRequest) (*pb.GetTrackerChangeResponse, error) {
	r.rec("GetTrackerChange u=%s c=%s n=%d", q.GetUsername(), q.GetConnection(), q.GetNumber())
	return &pb.GetTrackerChangeResponse{}, nil
}

func (r *recordingTracker) SubmitTrackerChange(_ context.Context, q *pb.SubmitTrackerChangeRequest) (*pb.SubmitTrackerChangeResponse, error) {
	r.rec("SubmitTrackerChange u=%s c=%s", q.GetUsername(), q.GetConnection())
	return &pb.SubmitTrackerChangeResponse{}, nil
}

func newTrackerRouteMux(t *testing.T) (*runtime.ServeMux, *recordingTracker) {
	t.Helper()
	srv := grpc.NewServer(
		grpc.Creds(auth.NewServerTransportCredentials(nil)),
		grpc.ChainUnaryInterceptor(auth.TransportIdentityUnaryInterceptor()),
	)
	rec := &recordingTracker{}
	pb.RegisterTrackerServiceServer(srv, rec)
	lis := auth.NewInternalListener()
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher))
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(lis.DialContext),
	}
	if err := pb.RegisterTrackerServiceHandlerFromEndpoint(context.Background(), mux, "passthrough:///containarium-internal", opts); err != nil {
		t.Fatal(err)
	}
	return mux, rec
}

// Connection resources and the data-plane verbs live under one prefix,
// /v1/tracker/connections/{username}/{connection}/..., so a verb word can only
// ever appear AFTER the connection name. A user or connection called
// "connections", "routes", "issues", ... must therefore never be read as a verb
// (or the reverse). This drives the real grpc-gateway mux with that adversarial
// vocabulary and pins which RPC each URL reaches and what it extracted.
func TestTrackerRoutes_NoAmbiguity(t *testing.T) {
	mux, rec := newTrackerRouteMux(t)

	names := []string{"connections", "status", "issues", "changes", "routes", "dispatch", "dispatches", "ordinary"}
	users := append([]string{"alice"}, names...)

	do := func(method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code, rec.take()
	}

	for _, u := range users {
		for _, c := range names {
			base := "/v1/tracker/connections/" + u + "/" + c
			cases := []struct{ method, path, body, want string }{
				{"GET", base, "", fmt.Sprintf("GetTrackerConnection u=%s name=%s", u, c)},
				{"GET", base + "/status", "", fmt.Sprintf("GetTrackerStatus u=%s name=%s", u, c)},
				{"PUT", base + "/routes/routes", `{"skillId":"s"}`, fmt.Sprintf("SetTrackerRoute u=%s c=%s scope=routes", u, c)},
				{"PUT", base + "/routes/bug", `{"skillId":"s"}`, fmt.Sprintf("SetTrackerRoute u=%s c=%s scope=bug", u, c)},
				{"GET", base + "/routes", "", fmt.Sprintf("ListTrackerRoutes u=%s c=%s", u, c)},
				{"DELETE", base + "/routes/bug", "", fmt.Sprintf("DeleteTrackerRoute u=%s c=%s scope=bug", u, c)},
				{"POST", base + "/dispatch", `{}`, fmt.Sprintf("DispatchTrackerIssues u=%s c=%s", u, c)},
				{"GET", base + "/dispatches", "", fmt.Sprintf("ListTrackerDispatches u=%s c=%s", u, c)},
				{"GET", base + "/issues/7", "", fmt.Sprintf("GetTrackerIssue u=%s c=%s n=7", u, c)},
				{"GET", base + "/issues", "", fmt.Sprintf("ListTrackerIssues u=%s c=%s", u, c)},
				{"POST", base + "/issues", `{"title":"t"}`, fmt.Sprintf("CreateTrackerIssue u=%s c=%s", u, c)},
				{"POST", base + "/issues/7/comments", `{"body":"b"}`, fmt.Sprintf("CommentOnTrackerIssue u=%s c=%s n=7", u, c)},
				{"POST", base + "/issues/7/claim", `{}`, fmt.Sprintf("ClaimTrackerIssue u=%s c=%s n=7", u, c)},
				{"POST", base + "/issues/7/labels", `{}`, fmt.Sprintf("SetTrackerIssueLabels u=%s c=%s n=7", u, c)},
				{"GET", base + "/changes/9", "", fmt.Sprintf("GetTrackerChange u=%s c=%s n=9", u, c)},
				{"POST", base + "/changes", `{"issue":1,"title":"t"}`, fmt.Sprintf("SubmitTrackerChange u=%s c=%s", u, c)},
			}
			for _, tc := range cases {
				code, got := do(tc.method, tc.path, tc.body)
				if code != http.StatusOK || got != tc.want {
					t.Errorf("%s %s -> HTTP %d, handler %q; want 200, %q", tc.method, tc.path, code, got, tc.want)
				}
			}
		}
	}

	// Connection CRUD that is not part of the ambiguity still resolves. The
	// recorder leaves these RPCs Unimplemented, so 501 means "routed".
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/v1/tracker/connections", `{"username":"alice","name":"work"}`},
		{"GET", "/v1/tracker/connections/alice", ""},
		{"DELETE", "/v1/tracker/connections/alice/work", ""},
	} {
		if code, _ := do(tc.method, tc.path, tc.body); code != http.StatusNotImplemented {
			t.Errorf("%s %s -> HTTP %d, want 501 (routed to an unimplemented handler)", tc.method, tc.path, code)
		}
	}
}

// The pre-nesting paths (/v1/tracker/{username}/{connection}/<verb>) were
// removed outright — no deprecation window, no alias. Pin the clean break so
// they cannot quietly come back.
func TestTrackerRoutes_OldPathsAreGone(t *testing.T) {
	mux, _ := newTrackerRouteMux(t)
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/v1/tracker/alice/work/routes/bug", `{"skillId":"s"}`},
		{"GET", "/v1/tracker/alice/work/routes", ""},
		{"DELETE", "/v1/tracker/alice/work/routes/bug", ""},
		{"POST", "/v1/tracker/alice/work/dispatch", `{}`},
		{"GET", "/v1/tracker/alice/work/dispatches", ""},
		{"GET", "/v1/tracker/alice/work/issues/7", ""},
		{"GET", "/v1/tracker/alice/work/issues", ""},
		{"POST", "/v1/tracker/alice/work/issues", `{}`},
		{"POST", "/v1/tracker/alice/work/issues/7/comments", `{}`},
		{"POST", "/v1/tracker/alice/work/issues/7/claim", `{}`},
		{"POST", "/v1/tracker/alice/work/issues/7/labels", `{}`},
		{"GET", "/v1/tracker/alice/work/changes/9", ""},
		{"POST", "/v1/tracker/alice/work/changes", `{}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s -> HTTP %d, want 404 (old path must stay removed)", tc.method, tc.path, w.Code)
		}
	}
}
