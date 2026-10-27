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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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
