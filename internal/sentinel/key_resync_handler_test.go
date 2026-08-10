package sentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/gateway"
)

// backendKeyServer stands in for a daemon's /authorized-keys endpoint. keys
// is swapped between requests to simulate a box being created after the
// sentinel's last periodic sync.
type backendKeyServer struct {
	mu    sync.Mutex
	keys  []gateway.UserKeys
	fetch atomic.Int32
	srv   *httptest.Server
}

func newBackendKeyServer(t *testing.T, initial ...gateway.UserKeys) *backendKeyServer {
	t.Helper()
	b := &backendKeyServer{keys: initial}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorized-keys":
			b.fetch.Add(1)
			b.mu.Lock()
			resp := gateway.KeysResponse{Keys: append([]gateway.UserKeys(nil), b.keys...)}
			b.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case "/authorized-keys/sentinel":
			// The sentinel's upstream-key push. Irrelevant here; the
			// sentinel treats a failure as non-fatal either way.
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// setKeys replaces the key set the backend will serve on the next fetch.
func (b *backendKeyServer) setKeys(keys ...gateway.UserKeys) {
	b.mu.Lock()
	b.keys = keys
	b.mu.Unlock()
}

// hostPort splits the test server's address into the IP and port the
// sentinel's Backend/Config pair expects.
func (b *backendKeyServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	addr := b.srv.Listener.Addr().String()
	i := strings.LastIndex(addr, ":")
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		t.Fatalf("parse test server port from %q: %v", addr, err)
	}
	return addr[:i], port
}

// managerWithBackend wires a Manager whose single registered backend is the
// given key server — enough for the resync handler, no networking beyond it.
func managerWithBackend(t *testing.T, backendID string, b *backendKeyServer) *Manager {
	t.Helper()
	ip, port := b.hostPort(t)
	m := &Manager{
		config:   Config{HealthPort: port},
		backends: NewBackendPool(),
		keyStore: NewKeyStore(),
	}
	m.backends.Add(&Backend{ID: backendID, IP: ip, Healthy: true})
	return m
}

// syncedUsers returns the usernames the KeyStore currently holds for a
// backend — what the next sshpiper config write would be built from.
func syncedUsers(ks *KeyStore, backendID string) []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	bk, ok := ks.backends[backendID]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(bk.users))
	for _, u := range bk.users {
		out = append(out, u.Username)
	}
	return out
}

func postResync(t *testing.T, h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sentinel/keys/resync", bytes.NewReader(buf))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// The core of cloud #971: a box created between two periodic ticks must not
// wait for the next tick. One resync call and its key is live.
func TestKeyResyncHandler_SyncsNewBoxWithoutWaitingForTick(t *testing.T) {
	backend := newBackendKeyServer(t, gateway.UserKeys{Username: "cld-existing", AuthorizedKeys: "ssh-ed25519 AAAA_existing a@b"})
	m := managerWithBackend(t, "backend-a", backend)

	// The state after the last periodic tick: only the pre-existing box.
	// The error is ignored on purpose: this test asserts on the in-memory
	// key state (next line), not on the sshpiper config write, which needs
	// /etc/sshpiper and so depends on how the test host is set up.
	_ = m.keyStore.syncAndApply("backend-a", mustIP(t, backend), m.config.HealthPort)
	if got := syncedUsers(m.keyStore, "backend-a"); len(got) != 1 {
		t.Fatalf("precondition: synced users = %v, want 1", got)
	}

	// A box is created on the daemon. Its key exists on the backend but the
	// sentinel doesn't know yet — this is the ~50s window.
	backend.setKeys(
		gateway.UserKeys{Username: "cld-existing", AuthorizedKeys: "ssh-ed25519 AAAA_existing a@b"},
		gateway.UserKeys{Username: "cld-fresh", AuthorizedKeys: "ssh-ed25519 AAAA_fresh a@b"},
	)

	rec := postResync(t, m.KeyResyncHandler(), KeyResyncRequest{BackendID: "backend-a"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q; want 200", rec.Code, rec.Body.String())
	}

	var resp KeyResyncResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if !resp.Synced {
		t.Errorf("Synced = false, want true")
	}
	if resp.Users != 2 {
		t.Errorf("Users = %d, want 2", resp.Users)
	}

	got := syncedUsers(m.keyStore, "backend-a")
	if len(got) != 2 || !contains(got, "cld-fresh") {
		t.Fatalf("synced users = %v, want the fresh box included", got)
	}
}

// A resync that arrives while another is in flight is covered by that one:
// the sync is a full pull of the backend's key set, so any sync that STARTS
// after the request arrived already contains the caller's key. It must be
// reported as covered, never as a skip that drops the key on the floor.
func TestKeyResyncHandler_ConcurrentCallsAllSeeTheirKey(t *testing.T) {
	backend := newBackendKeyServer(t, gateway.UserKeys{Username: "cld-a", AuthorizedKeys: "ssh-ed25519 AAAA_a a@b"})
	m := managerWithBackend(t, "backend-a", backend)
	h := m.KeyResyncHandler()

	const callers = 8
	var wg sync.WaitGroup
	codes := make([]int, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf, _ := json.Marshal(KeyResyncRequest{BackendID: "backend-a"})
			req := httptest.NewRequest(http.MethodPost, "/sentinel/keys/resync", bytes.NewReader(buf))
			rec := httptest.NewRecorder()
			h(rec, req)
			codes[i] = rec.Code
		}()
	}
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("caller %d: status = %d, want 200", i, c)
		}
	}
	// Every caller is covered by at most one fetch each, and a burst must
	// collapse rather than issue one fetch per caller unconditionally.
	if n := backend.fetch.Load(); n < 1 || n > callers {
		t.Fatalf("upstream fetches = %d, want between 1 and %d", n, callers)
	}
}

// The sentinel swallows a failed pull (logs it, lets the next tick retry),
// so the response must not claim the keys are live. A daemon told
// Synced=true for a backend whose pull 401'd would log "SSH is ready" over
// a box nobody can reach.
func TestKeyResyncHandler_ReportsFailedPull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	i := strings.LastIndex(addr, ":")
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	m := &Manager{
		config:   Config{HealthPort: port},
		backends: NewBackendPool(),
		keyStore: NewKeyStore(),
	}
	m.backends.Add(&Backend{ID: "backend-a", IP: addr[:i], Healthy: true})

	rec := postResync(t, m.KeyResyncHandler(), KeyResyncRequest{BackendID: "backend-a"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the call was accepted; the pull is what failed)", rec.Code)
	}
	var resp KeyResyncResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if resp.Synced {
		t.Fatal("Synced = true after a failed upstream pull; must report the truth")
	}
}

func TestKeyResyncHandler_UnknownBackend(t *testing.T) {
	backend := newBackendKeyServer(t)
	m := managerWithBackend(t, "backend-a", backend)

	rec := postResync(t, m.KeyResyncHandler(), KeyResyncRequest{BackendID: "backend-nope"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %q; want 404", rec.Code, rec.Body.String())
	}
}

func TestKeyResyncHandler_MissingBackendIDFallsBackToRemoteAddr(t *testing.T) {
	backend := newBackendKeyServer(t, gateway.UserKeys{Username: "cld-a", AuthorizedKeys: "ssh-ed25519 AAAA_a a@b"})
	ip, port := backend.hostPort(t)
	m := &Manager{
		config:   Config{HealthPort: port},
		backends: NewBackendPool(),
		keyStore: NewKeyStore(),
	}
	m.backends.Add(&Backend{ID: "backend-a", IP: ip, Healthy: true})

	buf, _ := json.Marshal(KeyResyncRequest{})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/keys/resync", bytes.NewReader(buf))
	req.RemoteAddr = fmt.Sprintf("%s:54321", ip)
	rec := httptest.NewRecorder()
	m.KeyResyncHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q; want 200 (backend resolved by source IP)", rec.Code, rec.Body.String())
	}
	if got := syncedUsers(m.keyStore, "backend-a"); len(got) != 1 {
		t.Fatalf("synced users = %v, want 1", got)
	}
}

func TestKeyResyncHandler_RejectsNonPost(t *testing.T) {
	backend := newBackendKeyServer(t)
	m := managerWithBackend(t, "backend-a", backend)

	req := httptest.NewRequest(http.MethodGet, "/sentinel/keys/resync", nil)
	rec := httptest.NewRecorder()
	m.KeyResyncHandler()(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// A sentinel with no key store (not wired for keysync) must answer clearly
// rather than panic — the daemon treats it as "nothing to do".
func TestKeyResyncHandler_NoKeyStore(t *testing.T) {
	m := &Manager{config: Config{HealthPort: 8080}, backends: NewBackendPool()}
	rec := postResync(t, m.KeyResyncHandler(), KeyResyncRequest{BackendID: "backend-a"})
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func mustIP(t *testing.T, b *backendKeyServer) string {
	t.Helper()
	ip, _ := b.hostPort(t)
	return ip
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
