package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakePeerDaemon is a peer that serves its own stack catalog and records the
// creates it is asked to perform.
type fakePeerDaemon struct {
	mu          sync.Mutex
	catalog     []string // nil with catalogCode set simulates an unreadable catalog
	catalogCode int
	creates     []string // stack of each real create received
	srv         *httptest.Server
}

func newFakePeerDaemon(t *testing.T, catalog ...string) *fakePeerDaemon {
	t.Helper()
	p := &fakePeerDaemon{catalog: catalog}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/stacks":
			if p.catalogCode != 0 {
				w.WriteHeader(p.catalogCode)
				return
			}
			type stack struct {
				ID string `json:"id"`
			}
			var out struct {
				Stacks []stack `json:"stacks"`
			}
			for _, id := range p.catalog {
				out.Stacks = append(out.Stacks, stack{ID: id})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/containers":
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				Stack string `json:"stack"`
			}
			_ = json.Unmarshal(raw, &body)
			p.creates = append(p.creates, body.Stack)
			_, _ = w.Write([]byte(`{"container":{"name":"alice-container","username":"alice"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakePeerDaemon) createsSeen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.creates...)
}

// serverWithPeer builds a daemon with one healthy peer in pool "gpu".
func serverWithPeer(p *fakePeerDaemon) *ContainerServer {
	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["remote"] = &PeerClient{ID: "remote", Addr: p.srv.Listener.Addr().String(), Pool: "gpu", Healthy: true, client: p.srv.Client()}
	pool.mu.Unlock()
	return &ContainerServer{peerPool: pool}
}

func createVia(t *testing.T, srv *ContainerServer, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	t.Helper()
	return dryRunNoPanic(t, srv, req)
}

// #2952: a --pool create that placement routes to a peer is validated against
// THAT peer's catalog. A stack only the peer defines is accepted...
func TestCreateContainer_PoolPlacedOnPeer_StackOnlyThePeerHasIsAccepted(t *testing.T) {
	peer := newFakePeerDaemon(t, "peer-only-stack", "nodejs")
	_, err := createVia(t, serverWithPeer(peer), &pb.CreateContainerRequest{Username: "alice", Pool: "gpu", Stack: "peer-only-stack"})
	if status.Code(err) == codes.InvalidArgument {
		t.Fatalf("a stack the peer defines was rejected against this daemon's catalog: %v", err)
	}
	if got := peer.createsSeen(); len(got) != 1 || got[0] != "peer-only-stack" {
		t.Fatalf("peer creates = %v, want exactly one create for peer-only-stack", got)
	}
}

// ...and a stack this daemon knows but the peer does not is rejected, naming
// the peer's valid stacks, before anything is provisioned: no create reaches the
// peer and no encrypted tenant storage is made on this daemon.
func TestCreateContainer_PoolPlacedOnPeer_UnknownOnThePeerProvisionsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *pb.CreateContainerRequest
	}{
		{"via pool", &pb.CreateContainerRequest{Username: "alice", Pool: "gpu", Stack: "nodejs"}},
		{"via explicit backend", &pb.CreateContainerRequest{Username: "alice", BackendId: "remote", Stack: "nodejs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newFakePeerDaemon(t, "python") // nodejs is NOT on the peer
			srv := serverWithPeer(peer)
			z := newZFSFake()
			keys := &fakeKeyProvider{key: aKey(t)}
			srv.keyProvider = keys
			srv.encryption = testHooks(t, z, keys, map[string]zfskey.KeyRef{})
			req := cloneCreateReq(tc.req)
			req.Encrypted = true

			_, err := createVia(t, srv, req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("got %v, want InvalidArgument", err)
			}
			for _, want := range []string{`"nodejs"`, "remote", "python"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should mention %q (the stack, the backend, the peer's valid stacks)", err, want)
				}
			}
			if got := peer.createsSeen(); len(got) != 0 {
				t.Errorf("the peer was sent %d create(s) for a stack it does not have", len(got))
			}
			if len(z.calls) != 0 || keys.wrapCall != 0 {
				t.Errorf("encrypted tenant storage was touched before the rejection: zfs calls %v, key wraps %d", z.calls, keys.wrapCall)
			}
		})
	}
}

// A peer whose catalog cannot be read must not block the create: the peer
// still validates for itself, which is the behaviour before this check.
func TestCreateContainer_PeerCatalogUnreadableFallsBackToForwarding(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*fakePeerDaemon)
	}{
		{"server error", func(p *fakePeerDaemon) { p.catalogCode = http.StatusInternalServerError }},
		{"empty catalog", func(p *fakePeerDaemon) { p.catalog = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newFakePeerDaemon(t, "nodejs")
			tc.set(peer)
			_, err := createVia(t, serverWithPeer(peer), &pb.CreateContainerRequest{Username: "alice", Pool: "gpu", Stack: "nodejs"})
			if err != nil {
				t.Fatalf("create failed although the peer's catalog was unreadable: %v", err)
			}
			if got := peer.createsSeen(); len(got) != 1 {
				t.Fatalf("peer creates = %v, want the create forwarded unchanged", got)
			}
		})
	}
}

// A dry run bound for a peer now checks the stack against the peer's catalog
// too, still without forwarding the dry run itself.
func TestCreateContainer_DryRunBoundForAPeerChecksThePeerCatalog(t *testing.T) {
	peer := newFakePeerDaemon(t, "python")
	srv := serverWithPeer(peer)

	_, err := createVia(t, srv, &pb.CreateContainerRequest{Username: "alice", Pool: "gpu", Stack: "nodejs", DryRun: true})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("dry run with a stack the peer lacks: got %v, want InvalidArgument", err)
	}

	resp, err := createVia(t, srv, &pb.CreateContainerRequest{Username: "alice", Pool: "gpu", Stack: "python", DryRun: true})
	if err != nil || !resp.GetDryRun() {
		t.Fatalf("dry run with a stack the peer has: resp=%v err=%v", resp, err)
	}
	if got := peer.createsSeen(); len(got) != 0 {
		t.Fatalf("a dry run reached the peer as %d real create(s)", len(got))
	}
	if !strings.Contains(resp.GetMessage(), "catalog") {
		t.Errorf("message %q should say the peer's catalog was checked", resp.GetMessage())
	}
}

var _ = context.Background
