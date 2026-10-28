//go:build integration

// Cross-tenant revocation (#3187): a tenant that drops a key from its own box
// revokes only the ssh_keys entry its own account owns. Adding another
// owner's public key to your box and then dropping it must leave that
// owner's entry active. Run against the real registry, because the scoping
// lives in its SQL:
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/ -run CrossTenant
package server

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func crossTenantServer(t *testing.T) (*ContainerServer, *sshauthz.PGKeyStore, *fakeAuthorizedKeys) {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping — this is a tenant " +
			"boundary, and a skipped test looks exactly like a passing one.")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS ssh_keys`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	keys, err := sshauthz.NewPGKeyStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewPGKeyStore: %v", err)
	}
	fs := newFakeAuthorizedKeys()
	keys.WithHolders(fs)
	fs.platform = "# platform"
	s := &ContainerServer{authorizedKeys: fs.ops(), sshKeyNow: func() time.Time { return caseClock }}
	s.SetSSHKeyRegistry(keys)
	return s, keys, fs
}

// keyState reads the registry row for pub: its owner and whether it is active.
func keyState(t *testing.T, keys *sshauthz.PGKeyStore, pub string) (owner string, active bool) {
	t.Helper()
	rec, err := sshauthz.NewKeyRecord(pub, "probe", sshauthz.SourceAPI, caseClock)
	if err != nil {
		t.Fatal(err)
	}
	row, err := keys.Lookup(context.Background(), rec.Fingerprint)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return row.Username, row.RevokedAt.IsZero()
}

func TestSSHKeys_CrossTenantDropKeepsOtherOwnersEntry(t *testing.T) {
	bobCtx := tenantWithScopes("bob", auth.ScopeSSHWrite)
	aliceCtx := tenantWithScopes("alice", auth.ScopeSSHWrite)

	for _, tc := range []struct {
		name string
		drop func(s *ContainerServer, bobKey, aliceKey string) error
	}{
		{"RemoveSSHKey", func(s *ContainerServer, bobKey, _ string) error {
			_, err := s.RemoveSSHKey(aliceCtx, &pb.RemoveSSHKeyRequest{Username: "alice", SshPublicKey: bobKey})
			return err
		}},
		{"SetSSHKeys", func(s *ContainerServer, _, aliceKey string) error {
			_, err := s.SetSSHKeys(aliceCtx, &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{aliceKey}})
			return err
		}},
		{"SetSSHKeys allow_empty", func(s *ContainerServer, _, _ string) error {
			_, err := s.SetSSHKeys(aliceCtx, &pb.SetSSHKeysRequest{Username: "alice", AllowEmpty: true})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, keys, fs := crossTenantServer(t)
			bobKey, aliceKey := newTestPubKey(t), newTestPubKey(t)

			// Bob registers his key on his own box.
			if _, err := s.AddSSHKey(bobCtx, &pb.AddSSHKeyRequest{Username: "bob", SshPublicKey: bobKey}); err != nil {
				t.Fatalf("bob AddSSHKey: %v", err)
			}
			// Alice copies bob's public key (it is public) onto her box,
			// next to her own.
			for _, k := range []string{aliceKey, bobKey} {
				if _, err := s.AddSSHKey(aliceCtx, &pb.AddSSHKeyRequest{Username: "alice", SshPublicKey: k}); err != nil {
					t.Fatalf("alice AddSSHKey: %v", err)
				}
			}
			if owner, active := keyState(t, keys, bobKey); owner != "bob" || !active {
				t.Fatalf("precondition: bob's key row = owner %q active %v, want bob, active", owner, active)
			}

			// Alice drops it from her box.
			if err := tc.drop(s, bobKey, aliceKey); err != nil {
				t.Fatalf("alice drop: %v", err)
			}
			for _, l := range fs.files["alice"] {
				if l == bobKey {
					t.Fatal("bob's key is still in alice's authorized_keys")
				}
			}

			// Bob's entry is untouched.
			if owner, active := keyState(t, keys, bobKey); owner != "bob" || !active {
				t.Fatalf("alice's drop revoked bob's registry entry: owner %q active %v", owner, active)
			}

			// Control: the owner's own drop still revokes, so the assertion
			// above is not passing because revocation does nothing at all.
			if _, err := s.RemoveSSHKey(bobCtx, &pb.RemoveSSHKeyRequest{Username: "bob", SshPublicKey: bobKey}); err != nil {
				t.Fatalf("bob RemoveSSHKey: %v", err)
			}
			if _, active := keyState(t, keys, bobKey); active {
				t.Fatal("the owner's own RemoveSSHKey did not revoke the key")
			}
		})
	}
}

// #3222, Alice-first order: alice adds bob's public key to her own box before
// bob registers it, so the registry row is hers; bob then adds it to his box.
// Alice dropping it must not revoke the access bob holds in his own box.
func TestSSHKeys_AliceFirstDropDoesNotRevokeBobsKey(t *testing.T) {
	bobCtx := tenantWithScopes("bob", auth.ScopeSSHWrite)
	aliceCtx := tenantWithScopes("alice", auth.ScopeSSHWrite)

	setup := func(t *testing.T) (*ContainerServer, *sshauthz.PGKeyStore, *fakeAuthorizedKeys, string, string) {
		s, keys, fs := crossTenantServer(t)
		bobKey, aliceKey := newTestPubKey(t), newTestPubKey(t)
		for _, k := range []string{aliceKey, bobKey} {
			if _, err := s.AddSSHKey(aliceCtx, &pb.AddSSHKeyRequest{Username: "alice", SshPublicKey: k}); err != nil {
				t.Fatalf("alice AddSSHKey: %v", err)
			}
		}
		if _, err := s.AddSSHKey(bobCtx, &pb.AddSSHKeyRequest{Username: "bob", SshPublicKey: bobKey}); err != nil {
			t.Fatalf("bob AddSSHKey: %v", err)
		}
		if owner, active := keyState(t, keys, bobKey); owner != "alice" || !active {
			t.Fatalf("precondition: row = owner %q active %v, want alice, active", owner, active)
		}
		return s, keys, fs, bobKey, aliceKey
	}

	t.Run("RemoveSSHKey is refused and changes nothing", func(t *testing.T) {
		s, keys, fs, bobKey, _ := setup(t)
		_, err := s.RemoveSSHKey(aliceCtx, &pb.RemoveSSHKeyRequest{Username: "alice", SshPublicKey: bobKey})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("RemoveSSHKey = %v, want FailedPrecondition", err)
		}
		if strings.Contains(err.Error(), "bob") {
			t.Fatalf("the error must not name the other holder: %v", err)
		}
		if _, active := keyState(t, keys, bobKey); !active {
			t.Fatal("alice's RemoveSSHKey revoked a key bob holds")
		}
		if !slices.Contains(fs.files["alice"], bobKey) || !slices.Contains(fs.files["bob"], bobKey) {
			t.Fatal("a refused remove must leave both authorized_keys files alone")
		}
	})

	t.Run("SetSSHKeys drops only alice's entry", func(t *testing.T) {
		s, keys, fs, bobKey, aliceKey := setup(t)
		if _, err := s.SetSSHKeys(aliceCtx, &pb.SetSSHKeysRequest{Username: "alice", SshPublicKeys: []string{aliceKey}}); err != nil {
			t.Fatalf("SetSSHKeys: %v", err)
		}
		if slices.Contains(fs.files["alice"], bobKey) {
			t.Fatal("alice's own authorized_keys still holds the dropped key")
		}
		if !slices.Contains(fs.files["bob"], bobKey) {
			t.Fatal("bob's authorized_keys lost his key")
		}
		if _, active := keyState(t, keys, bobKey); !active {
			t.Fatal("alice's SetSSHKeys revoked a key bob holds")
		}
	})

	t.Run("sole holder still revokes", func(t *testing.T) {
		s, keys, fs, bobKey, _ := setup(t)
		if _, err := s.RemoveSSHKey(bobCtx, &pb.RemoveSSHKeyRequest{Username: "bob", SshPublicKey: bobKey}); err != nil {
			t.Fatalf("bob RemoveSSHKey (non-owner, never refused): %v", err)
		}
		if _, err := s.RemoveSSHKey(aliceCtx, &pb.RemoveSSHKeyRequest{Username: "alice", SshPublicKey: bobKey}); err != nil {
			t.Fatalf("alice RemoveSSHKey as sole holder: %v", err)
		}
		if _, active := keyState(t, keys, bobKey); active {
			t.Fatal("the sole holder's RemoveSSHKey did not revoke the key")
		}
		_ = fs
	})
}
