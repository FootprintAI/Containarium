package server

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
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
