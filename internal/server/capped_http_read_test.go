package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/limitio"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3469: response bodies the daemon reads whole from a peer daemon, a box's
// A2A server or the sentinel are capped at limitio.MaxHTTPResponseBytes.
//
// Each over-cap test sends a body that is valid for the path (real JSON,
// padded with trailing whitespace past the cap), so without the cap the call
// would succeed; with it, the call stops at the cap and reports
// limitio.ErrTooLarge.

// padTo returns body followed by spaces up to n bytes in total.
func padTo(body []byte, n int64) []byte {
	if int64(len(body)) >= n {
		return body
	}
	return append(body, []byte(strings.Repeat(" ", int(n-int64(len(body)))))...)
}

func overCap(body []byte) []byte { return padTo(body, limitio.MaxHTTPResponseBytes+1) }

// bodyServer answers every request with status and body.
func bodyServer(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func peerFor(srv *httptest.Server) *PeerClient {
	return &PeerClient{ID: "peer-a", Addr: srv.Listener.Addr().String(), Healthy: true, client: srv.Client()}
}

func a2aArtifactJSON(t *testing.T) []byte {
	t.Helper()
	b, err := protojson.Marshal(&pb.AgentArtifact{TaskId: "task-1", State: pb.AgentTaskState_AGENT_TASK_STATE_COMPLETED})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSendA2ATask_ExactCapUnchanged(t *testing.T) {
	srv := bodyServer(t, http.StatusOK, padTo(a2aArtifactJSON(t), limitio.MaxHTTPResponseBytes))
	art, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "task-1"}, "box-secret")
	if err != nil {
		t.Fatalf("sendA2ATask at exactly the cap: %v", err)
	}
	if art.TaskId != "task-1" {
		t.Fatalf("task_id = %q", art.TaskId)
	}
}

func TestSendA2ATask_OverCapStopsAtCap(t *testing.T) {
	srv := bodyServer(t, http.StatusOK, overCap(a2aArtifactJSON(t)))
	_, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "task-1"}, "box-secret")
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
}

func TestSendA2ATask_OverCapErrorStatusStopsAtCap(t *testing.T) {
	srv := bodyServer(t, http.StatusBadGateway, overCap([]byte("boom")))
	_, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "task-1"}, "box-secret")
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
}

func TestPeerForwardRequest_UnderCapUnchanged(t *testing.T) {
	srv := bodyServer(t, http.StatusAccepted, []byte(`{"ok":true}`))
	body, code, err := peerFor(srv).ForwardRequest(http.MethodGet, "/v1/x", "", nil)
	if err != nil || code != http.StatusAccepted || string(body) != `{"ok":true}` {
		t.Fatalf("ForwardRequest = %q, %d, %v", body, code, err)
	}
}

func TestPeerForwardRequest_OverCapStopsAtCap(t *testing.T) {
	srv := bodyServer(t, http.StatusOK, overCap([]byte(`{"ok":true}`)))
	body, code, err := peerFor(srv).ForwardRequest(http.MethodGet, "/v1/x", "", nil)
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if code != http.StatusOK {
		t.Fatalf("status = %d, want the peer's status still reported", code)
	}
	if body != nil {
		t.Fatalf("got %d body bytes alongside the error, want none", len(body))
	}
}

func TestPeerFetchContainers_OverCapStopsAtCap(t *testing.T) {
	srv := bodyServer(t, http.StatusOK, overCap([]byte(`{"containers":[]}`)))
	_, err := peerFor(srv).fetchContainers("")
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
}

func TestPeerForwardCreateContainer_OverCapStopsAtCap(t *testing.T) {
	srv := bodyServer(t, http.StatusOK, overCap([]byte(`{"container":{"name":"alice"}}`)))
	_, err := peerFor(srv).ForwardCreateContainer("", &pb.CreateContainerRequest{Username: "alice"})
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
}

func TestPeerForwardCreateContainer_UnderCapUnchanged(t *testing.T) {
	srv := bodyServer(t, http.StatusOK, []byte(`{"container":{"name":"alice"}}`))
	out, err := peerFor(srv).ForwardCreateContainer("", &pb.CreateContainerRequest{Username: "alice"})
	if err != nil || out.GetContainer().GetName() != "alice" || out.GetContainer().GetBackendId() != "peer-a" {
		t.Fatalf("ForwardCreateContainer = %+v, %v", out, err)
	}
}

// discover drops an over-cap sentinel response — even a validly signed one —
// and leaves the peer map unchanged.
func TestPeerPoolDiscover_OverCapLeavesPoolUnchanged(t *testing.T) {
	setDiscoverySecret(t, discoverySignSecret)
	payload, err := json.Marshal(map[string]any{"peers": []any{
		map[string]any{"id": "tunnel-x", "proxy_path": "/peer/tunnel-x", "healthy": true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := overCap(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sentinel/peers" {
			http.NotFound(w, r)
			return
		}
		auth.SignSentinelResponse(w, []byte(discoverySignSecret), body)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	p := NewPeerPool("local", srv.URL, nil, "")
	p.discover()
	if got := p.Snapshot(); len(got) != 0 {
		t.Fatalf("over-cap discovery response was applied: %+v", got)
	}
}

func TestFetchPeerPKI_OverCapStopsAtCap(t *testing.T) {
	body, err := json.Marshal(map[string]string{"cert_pem": "c", "key_pem": "k", "ca_pem": "ca"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(overCap(body))
	}))
	defer srv.Close()
	_, err = FetchPeerPKI(context.Background(), srv.URL, "peer-a", []byte(discoverySignSecret))
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
}

// The sentinel registration helpers read only a non-2xx body, into an error
// message; that read keeps a short prefix instead of the whole body.
func TestPrimaryRegister_ErrorBodyKeptShort(t *testing.T) {
	big := strings.Repeat("e", maxRegisterErrorBodyBytes+100)
	srv := bodyServer(t, http.StatusInternalServerError, []byte(big))
	secret := []byte(discoverySignSecret)
	for name, call := range map[string]func() error{
		"post": func() error {
			return postJSON(context.Background(), srv.Client(), srv.URL, map[string]string{}, secret)
		},
		"put":    func() error { return putRequest(context.Background(), srv.Client(), srv.URL, nil, secret) },
		"delete": func() error { return deleteRequest(context.Background(), srv.Client(), srv.URL, secret) },
	} {
		err := call()
		var se *httpStatusError
		if !errors.As(err, &se) || se.code != http.StatusInternalServerError {
			t.Fatalf("%s: err = %v, want *httpStatusError 500", name, err)
		}
		if len(se.body) != maxRegisterErrorBodyBytes {
			t.Fatalf("%s: kept %d body bytes, want %d", name, len(se.body), maxRegisterErrorBodyBytes)
		}
	}
}

func TestPrimaryRegister_ErrorBodyUnderCapUnchanged(t *testing.T) {
	srv := bodyServer(t, http.StatusConflict, []byte("taken"))
	err := postJSON(context.Background(), srv.Client(), srv.URL, map[string]string{}, []byte(discoverySignSecret))
	var se *httpStatusError
	if !errors.As(err, &se) || se.code != http.StatusConflict || se.body != "taken" {
		t.Fatalf("err = %v, want *httpStatusError{409, taken}", err)
	}
}

// An endless body: the call must return at the cap, not keep draining the
// rest of the body until the caller's deadline.
func TestSendA2ATask_EndlessBodyReturnsAtCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat(" ", 64<<10))
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	_, err := sendA2ATask(ctx, srv.URL, &pb.AgentTask{Id: "task-1"}, "box-secret")
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("returned after %s: kept reading past the cap", elapsed)
	}
}
