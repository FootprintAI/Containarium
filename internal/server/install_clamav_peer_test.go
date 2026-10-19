package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/security"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #2683: InstallClamav must reach the backend that OWNS the box, the way
// TriggerClamavScan does; a box on a peer used to fail with a local lookup
// error because the install only ever ran on the daemon that was asked.

// fakeOwningPeer serves what a peer backend serves for this RPC: its container
// list (so FindContainerPeer can find the box) and the install route.
type fakeOwningPeer struct {
	srv         *httptest.Server
	installHits atomic.Int32
	gotAuth     atomic.Value // string
	gotBody     atomic.Value // string
	installCode int
	installBody string
	installWait time.Duration
}

func newFakeOwningPeer(t *testing.T, boxes ...string) *fakeOwningPeer {
	t.Helper()
	f := &fakeOwningPeer{installCode: 200, installBody: `{"outcome":"CLAMAV_INSTALL_OUTCOME_INSTALLED","message":"installed on the peer"}`}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/containers":
			var cs []map[string]any
			for _, b := range boxes {
				cs = append(cs, map[string]any{"name": b, "username": strings.TrimSuffix(b, "-container"), "state": "CONTAINER_STATE_RUNNING"})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"containers": cs})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/security/clamav-install":
			f.installHits.Add(1)
			f.gotAuth.Store(r.Header.Get("Authorization"))
			b, _ := io.ReadAll(r.Body)
			f.gotBody.Store(string(b))
			time.Sleep(f.installWait)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.installCode)
			_, _ = w.Write([]byte(f.installBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOwningPeer) client() *PeerClient {
	return &PeerClient{ID: "peer-a", Addr: f.srv.Listener.Addr().String(), Healthy: true, client: f.srv.Client()}
}

func serverWithPeers(peers ...*PeerClient) *SecurityServer {
	pp := NewPeerPool("local-vm", "", nil, "")
	for _, p := range peers {
		pp.peers[p.ID] = p
	}
	// incusClient stays nil: a request that wrongly runs locally answers
	// Unavailable, so the tests below can tell the two paths apart.
	return &SecurityServer{peerPool: pp}
}

func TestInstallClamav_ForwardsToThePeerThatOwnsTheBox(t *testing.T) {
	peer := newFakeOwningPeer(t, "alice-container")
	s := serverWithPeers(peer.client())

	resp, err := s.InstallClamav(tenantCtx("alice"), &pb.InstallClamavRequest{ContainerName: "alice-container"})

	if err != nil {
		t.Fatalf("InstallClamav: %v", err)
	}
	if resp.GetOutcome() != pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_INSTALLED || resp.GetMessage() != "installed on the peer" {
		t.Errorf("response = %v, want the peer's outcome and message", resp)
	}
	if got := peer.installHits.Load(); got != 1 {
		t.Errorf("peer install hits = %d, want exactly 1", got)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(peer.gotBody.Load().(string)), &body); err != nil || body["container_name"] != "alice-container" {
		t.Errorf("peer got body %q (%v), want {container_name: alice-container} as valid JSON", peer.gotBody.Load(), err)
	}
}

func TestInstallClamav_ForwardCarriesAJSONSafeName(t *testing.T) {
	// The existing scan forwarder formats the name into the JSON by hand; the
	// install forwarder must marshal it, so a quote in a name cannot break (or
	// inject into) the body.
	peer := newFakeOwningPeer(t, `we"ird-container`)
	s := serverWithPeers(peer.client())
	_, _ = s.InstallClamav(adminCtx(), &pb.InstallClamavRequest{ContainerName: `we"ird-container`})
	var body map[string]string
	if err := json.Unmarshal([]byte(peer.gotBody.Load().(string)), &body); err != nil {
		t.Fatalf("forwarded body is not valid JSON: %q (%v)", peer.gotBody.Load(), err)
	}
	if body["container_name"] != `we"ird-container` {
		t.Errorf("container_name = %q, want it round-tripped intact", body["container_name"])
	}
}

func TestInstallClamav_AnOlderPeerWithoutTheRouteIsUnimplemented(t *testing.T) {
	peer := newFakeOwningPeer(t, "alice-container")
	peer.installCode, peer.installBody = 404, `{"code":5,"message":"Not Found"}`
	s := serverWithPeers(peer.client())

	_, err := s.InstallClamav(tenantCtx("alice"), &pb.InstallClamavRequest{ContainerName: "alice-container"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("got %v, want Unimplemented: an older backend is not a failed install", err)
	}
}

func TestInstallClamav_AnUnreachableBackendIsNotAnsweredLocally(t *testing.T) {
	// The only candidate peer is unhealthy: the box may live there, so the call
	// must say that, and must not fall through to the local lookup (which would
	// report the box as missing).
	s := serverWithPeers(&PeerClient{ID: "peer-down", Healthy: false})

	_, err := s.InstallClamav(tenantCtx("alice"), &pb.InstallClamavRequest{ContainerName: "alice-container"})
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("got %v, want an error naming the unreachable backend", err)
	}
}

func TestInstallClamav_NoPeerOwnsTheBoxRunsLocally(t *testing.T) {
	peer := newFakeOwningPeer(t /* owns nothing */)
	s := serverWithPeers(peer.client())

	_, err := s.InstallClamav(tenantCtx("alice"), &pb.InstallClamavRequest{ContainerName: "alice-container"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable (the local path, no runtime in this test)", err)
	}
	if peer.installHits.Load() != 0 {
		t.Error("a peer that does not own the box must not be sent the install")
	}
}

// An install can take minutes; the peer client has a 30 s overall timeout, so
// the forwarded call must not be bound by it.
func TestInstallClamav_ForwardIsNotCutShortByThePeerClientTimeout(t *testing.T) {
	peer := newFakeOwningPeer(t, "alice-container")
	peer.installWait = 300 * time.Millisecond
	pc := peer.client()
	short := *pc.client
	short.Timeout = 50 * time.Millisecond
	pc.client = &short
	s := serverWithPeers(pc)

	// The container list read is a separate short call, so give only the
	// install a slow server: the list answers at once.
	resp, err := s.InstallClamav(tenantCtx("alice"), &pb.InstallClamavRequest{ContainerName: "alice-container"})
	if err != nil {
		t.Fatalf("a slow install must still complete: %v", err)
	}
	if resp.GetOutcome() != pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_INSTALLED {
		t.Errorf("outcome = %v", resp.GetOutcome())
	}
}

func TestInstallClamav_AuthzIsCheckedBeforeAnyForward(t *testing.T) {
	peer := newFakeOwningPeer(t, "bob-container")
	s := serverWithPeers(peer.client())
	_, err := s.InstallClamav(tenantCtx("alice"), &pb.InstallClamavRequest{ContainerName: "bob-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied for another tenant's box", err)
	}
	if peer.installHits.Load() != 0 {
		t.Error("an unauthorized request must never reach a peer")
	}
}

// #2683, second point: a per-box scan started for a box on a peer is executed by
// the peer that owns the box (the trigger is forwarded; the peer enqueues it on
// ITS scanner and runs it with ITS runtime), never on the daemon that was asked.
// The local scanner here is a zero value with no store: touching it would panic.
func TestTriggerClamavScan_ForwardsToThePeerThatOwnsTheBox(t *testing.T) {
	var scanHits atomic.Int32
	var gotBody atomic.Value
	peer := newFakeOwningPeer(t, "alice-container")
	inner := peer.srv.Config.Handler
	peer.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/security/clamav-scan" {
			scanHits.Add(1)
			b, _ := io.ReadAll(r.Body)
			gotBody.Store(string(b))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"message":"queued on the peer","scannedCount":1}`))
			return
		}
		inner.ServeHTTP(w, r)
	})
	s := serverWithPeers(peer.client())
	s.scanner = &security.Scanner{}

	resp, err := s.TriggerClamavScan(tenantCtx("alice"), &pb.TriggerClamavScanRequest{ContainerName: "alice-container"})

	if err != nil {
		t.Fatalf("TriggerClamavScan: %v", err)
	}
	if !strings.Contains(resp.GetMessage(), "peer") {
		t.Errorf("message = %q, want it to say the scan was queued on the peer", resp.GetMessage())
	}
	if scanHits.Load() != 1 {
		t.Errorf("peer scan hits = %d, want exactly 1 (the owning peer runs the scan)", scanHits.Load())
	}
	if !strings.Contains(gotBody.Load().(string), "alice-container") {
		t.Errorf("peer got body %q, want the box name", gotBody.Load())
	}
}
