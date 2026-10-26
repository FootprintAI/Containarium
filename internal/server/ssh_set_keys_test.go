package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/footprintai/containarium/internal/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SetSSHKeys (#2945): replace-all for a box user's authorized keys.

func TestSetSSHKeys_RemovedKeysAreRevokedAndKeptKeysRegistered(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	fs.platform = "# platform"
	s := testServerWithRegistry(reg, fs)
	a, b := newTestPubKey(t), newTestPubKey(t)
	fs.files["alice"] = []string{a, b, fs.platform}
	ctx := tenantWithScopes("alice", auth.ScopeSSHWrite)

	resp, err := s.SetSSHKeys(ctx, &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{b}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RemovedKeys != 1 {
		t.Fatalf("removed = %d, want 1", resp.RemovedKeys)
	}
	if len(reg.revoked) != 1 || reg.revoked[0].rec.PublicKey != a {
		t.Fatalf("revoked = %+v, want only key A", reg.revoked)
	}
	if len(reg.registered) != 1 || reg.registered[0].PublicKey != b {
		t.Fatalf("registered = %+v, want key B", reg.registered)
	}
	for _, r := range reg.revoked {
		if r.rec.PublicKey == fs.platform {
			t.Fatal("platform key revoked")
		}
	}
}

func TestSetSSHKeys_EmptyListNeedsExplicitFlag(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	ctx := tenantWithScopes("alice", auth.ScopeSSHWrite)

	_, err := s.SetSSHKeys(ctx, &pb.SetSSHKeysRequest{Username: "alice"})
	if status.Code(err) != codes.InvalidArgument || fs.replaceCalls != 0 {
		t.Fatalf("omitted list: err=%v replaceCalls=%d, want InvalidArgument and no write", err, fs.replaceCalls)
	}
	_, err = s.SetSSHKeys(ctx, &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{newTestPubKey(t)}, AllowEmpty: true})
	if status.Code(err) != codes.InvalidArgument || fs.replaceCalls != 0 {
		t.Fatalf("keys plus allow_empty: err=%v, want InvalidArgument and no write", err)
	}
	if _, err := s.SetSSHKeys(ctx, &pb.SetSSHKeysRequest{Username: "alice", AllowEmpty: true}); err != nil {
		t.Fatalf("explicit empty: %v", err)
	}
	if fs.replaceCalls != 1 {
		t.Fatalf("replaceCalls = %d, want 1", fs.replaceCalls)
	}
}

func TestSetSSHKeys_InvalidKeyChangesNothing(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	good := newTestPubKey(t)
	ctx := tenantWithScopes("alice", auth.ScopeSSHWrite)
	for name, bad := range map[string]string{
		"malformed": "ssh-ed25519 nope",
		"command":   `command="id" ` + newTestPubKey(t),
		"multiline": newTestPubKey(t) + "\n" + newTestPubKey(t),
	} {
		_, err := s.SetSSHKeys(ctx, &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{good, bad}})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
	if fs.replaceCalls != 0 || len(reg.registered) != 0 || len(reg.revoked) != 0 {
		t.Fatalf("rejected calls had effects: replace=%d reg=%d rev=%d", fs.replaceCalls, len(reg.registered), len(reg.revoked))
	}
}

func TestSetSSHKeys_SameAuthorizationAsAddSSHKey(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	req := &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{newTestPubKey(t)}}

	// Missing ssh:write scope.
	if _, err := s.SetSSHKeys(tenantWithScopes("alice", auth.ScopeContainersWrite), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no scope: %v", err)
	}
	// Another tenant's box.
	if _, err := s.SetSSHKeys(tenantWithScopes("mallory", auth.ScopeSSHWrite), req); err == nil {
		t.Fatal("cross-tenant call allowed")
	}
	if fs.replaceCalls != 0 || len(reg.registered)+len(reg.revoked) != 0 {
		t.Fatal("refused calls had effects")
	}
}

// Revoke fails => the file is untouched and a retry still sees the keys.
func TestSetSSHKeys_RevokeFailureLeavesFileAndRetryRevokes(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	fs.platform = "# platform"
	s := testServerWithRegistry(reg, fs)
	a, b := newTestPubKey(t), newTestPubKey(t)
	fs.files["alice"] = []string{a, b, fs.platform}
	ctx := tenantWithScopes("alice", auth.ScopeSSHWrite)
	req := &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{b}}

	reg.err = errors.New("db down")
	if _, err := s.SetSSHKeys(ctx, req); err == nil {
		t.Fatal("want error when revocation cannot be recorded")
	}
	if got := fs.files["alice"]; len(got) != 3 || got[0] != a {
		t.Fatalf("file changed despite revoke failure: %v", got)
	}

	reg.err = nil
	if _, err := s.SetSSHKeys(ctx, req); err != nil {
		t.Fatal(err)
	}
	if len(reg.revoked) != 1 || reg.revoked[0].rec.PublicKey != a {
		t.Fatalf("retry did not revoke A: %+v", reg.revoked)
	}
}

func TestSetSSHKeys_RejectsTooManyKeys(t *testing.T) {
	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	var keys []string
	for i := 0; i < 101; i++ {
		keys = append(keys, newTestPubKey(t))
	}
	_, err := s.SetSSHKeys(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: keys})
	if status.Code(err) != codes.InvalidArgument || fs.replaceCalls != 0 {
		t.Fatalf("err=%v replaceCalls=%d", err, fs.replaceCalls)
	}
}

// A successful Set tells the sentinel to resync (a revoked key left in
// sshpiper's table stays a working credential until it does).
func TestSetSSHKeys_NotifiesSentinel(t *testing.T) {
	var reasons atomic.Value
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("/sentinel/keys/resync", auth.SentinelHMACMiddleware(testHMACSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sentinel.KeyResyncRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		reasons.Store(req.Reason)
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(sentinel.KeyResyncResponse{Synced: true})
	})))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sentinelHMACSecretOnce.Do(func() {})
	prev := sentinelHMACSecret
	sentinelHMACSecret = testHMACSecret
	t.Cleanup(func() { sentinelHMACSecret = prev })

	reg, fs := &recordingRegistry{}, newFakeAuthorizedKeys()
	s := testServerWithRegistry(reg, fs)
	s.peerPool = NewPeerPool("backend-a", srv.URL, nil, "pool-a")
	if _, err := s.SetSSHKeys(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{newTestPubKey(t)}}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || reasons.Load() != "set_ssh_keys alice" {
		t.Fatalf("hits=%d reason=%v", hits.Load(), reasons.Load())
	}
}

// Registry work happens inside the file layer's critical section, so two
// concurrent Sets cannot interleave a Register after the other's Revoke.
type sectionRegistry struct {
	recordingRegistry
	fs          *fakeAuthorizedKeys
	outsideCall bool
}

func (r *sectionRegistry) Register(ctx context.Context, rec sshauthz.KeyRecord) error {
	if !r.fs.inReplace {
		r.outsideCall = true
	}
	return r.recordingRegistry.Register(ctx, rec)
}

func (r *sectionRegistry) Revoke(ctx context.Context, rec sshauthz.KeyRecord, at time.Time) error {
	if !r.fs.inReplace {
		r.outsideCall = true
	}
	return r.recordingRegistry.Revoke(ctx, rec, at)
}

func TestSetSSHKeys_RegistryWorkRunsInsideCriticalSection(t *testing.T) {
	fs := newFakeAuthorizedKeys()
	reg := &sectionRegistry{fs: fs}
	s := &ContainerServer{authorizedKeys: fs.ops(), sshKeyNow: func() time.Time { return caseClock }}
	s.SetSSHKeyRegistry(reg)
	a, b := newTestPubKey(t), newTestPubKey(t)
	fs.files["alice"] = []string{a}

	if _, err := s.SetSSHKeys(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{b}}); err != nil {
		t.Fatal(err)
	}
	if len(reg.registered) != 1 || len(reg.revoked) != 1 {
		t.Fatalf("registered=%d revoked=%d", len(reg.registered), len(reg.revoked))
	}
	if reg.outsideCall {
		t.Fatal("registry called outside the per-user critical section")
	}
}

// A slow registry is cut off, so it cannot hold the per-user lock forever.
type blockingRegistry struct{}

func (blockingRegistry) Register(ctx context.Context, _ sshauthz.KeyRecord) error {
	<-ctx.Done()
	return ctx.Err()
}

func (blockingRegistry) Revoke(ctx context.Context, _ sshauthz.KeyRecord, _ time.Time) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestSetSSHKeys_RegistryCallsAreTimeBounded(t *testing.T) {
	prev := setSSHKeysRegistryTimeout
	setSSHKeysRegistryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { setSSHKeysRegistryTimeout = prev })

	fs := newFakeAuthorizedKeys()
	s := &ContainerServer{authorizedKeys: fs.ops(), sshKeyNow: func() time.Time { return caseClock }}
	s.SetSSHKeyRegistry(blockingRegistry{})
	a, b := newTestPubKey(t), newTestPubKey(t)
	fs.files["alice"] = []string{a}
	ctx := tenantWithScopes("alice", auth.ScopeSSHWrite)

	for name, keys := range map[string][]string{"revoke": {b}, "register": {a}} {
		start := time.Now()
		_, err := s.SetSSHKeys(ctx, &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: keys})
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v, want deadline exceeded", name, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s: took %v", name, time.Since(start))
		}
	}
}
