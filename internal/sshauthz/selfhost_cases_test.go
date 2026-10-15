package sshauthz

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The self-host decider table (#2517, done-when 1) is shared by the unit
// run (in-memory key store) and the integration run (real Postgres), so
// both halves answer the same question: given these local facts and this
// registry row, what is the decision and the reason?

var caseNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

type fakeBoxes struct {
	names map[string]bool
	err   error
}

func (f fakeBoxes) ExistingContainerNames() (map[string]bool, error) { return f.names, f.err }

type fakeCollaborators struct {
	rows map[string]bool // "<container>/<collaborator>"
	err  error
}

func (f fakeCollaborators) CollaboratorExists(_ context.Context, containerName, collaboratorUsername string) (bool, error) {
	return f.rows[containerName+"/"+collaboratorUsername], f.err
}

// testKey returns a fresh ed25519 authorized_keys line.
func testKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(pk))
}

// writeHome creates <root>/<user>/.ssh/authorized_keys with content.
func writeHome(t *testing.T, root, user, content string) {
	t.Helper()
	dir := filepath.Join(root, user, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type deciderCase struct {
	name string

	login         string
	homeAccount   bool // jump account present with a non-empty authorized_keys
	boxes         map[string]bool
	boxesErr      bool
	collaborators map[string]bool

	registered bool          // a registry row exists for the offered key
	revoked    bool          // that row is revoked
	age        time.Duration // caseNow - created_at
	keyType    pb.SSHKeyType // stored key type (the offered key is ed25519 on the wire either way)
	maxKeyAge  time.Duration
	noCred     bool // request carries a certificate instead of a public key

	wantDecision pb.SSHAuthzDecision
	wantReason   pb.SSHDenyReason
	wantUserID   string
}

var (
	allow = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
	deny  = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
	none  = pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED

	noAccess   = pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS
	unknownKey = pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY
	expired    = pb.SSHDenyReason_SSH_DENY_REASON_KEY_EXPIRED

	ed = pb.SSHKeyType_SSH_KEY_TYPE_ED25519
	sk = pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519
)

var aliceBox = map[string]bool{"alice-container": true}

func deciderCases() []deciderCase {
	day := 24 * time.Hour
	return []deciderCase{
		// Local facts.
		{name: "owner, registered key → allow", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, keyType: ed, wantDecision: allow, wantReason: none, wantUserID: "alice"},
		{name: "no jump account → no_access", login: "alice", homeAccount: false, boxes: aliceBox,
			registered: true, keyType: ed, wantDecision: deny, wantReason: noAccess},
		{name: "orphan: account but box deleted → no_access", login: "alice", homeAccount: true, boxes: map[string]bool{},
			registered: true, keyType: ed, wantDecision: deny, wantReason: noAccess},
		{name: "box snapshot error fails closed → no_access", login: "alice", homeAccount: true, boxesErr: true,
			registered: true, keyType: ed, wantDecision: deny, wantReason: noAccess},
		{name: "unsafe login → no_access", login: "../alice", homeAccount: false, boxes: aliceBox,
			registered: true, keyType: ed, wantDecision: deny, wantReason: noAccess},
		{name: "empty login → no_access", login: "", boxes: aliceBox,
			registered: true, keyType: ed, wantDecision: deny, wantReason: noAccess},
		{name: "collaborator with row → allow as collaborator", login: "alice-container-bob", homeAccount: true, boxes: aliceBox,
			collaborators: map[string]bool{"alice-container/bob": true},
			registered:    true, keyType: ed, wantDecision: allow, wantReason: none, wantUserID: "bob"},
		{name: "collaborator without row → no_access", login: "alice-container-bob", homeAccount: true, boxes: aliceBox,
			collaborators: map[string]bool{},
			registered:    true, keyType: ed, wantDecision: deny, wantReason: noAccess},
		{name: "collaborator, owner box deleted → no_access", login: "alice-container-bob", homeAccount: true, boxes: map[string]bool{},
			collaborators: map[string]bool{"alice-container/bob": true},
			registered:    true, keyType: ed, wantDecision: deny, wantReason: noAccess},

		// Registry.
		{name: "unregistered key → unknown_key", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: false, wantDecision: deny, wantReason: unknownKey, wantUserID: "alice"},
		{name: "certificate credential → unknown_key", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, keyType: ed, noCred: true, wantDecision: deny, wantReason: unknownKey, wantUserID: "alice"},
		{name: "revoked key → unknown_key", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, revoked: true, keyType: ed, wantDecision: deny, wantReason: unknownKey, wantUserID: "alice"},

		// Local policy.
		{name: "max age 0 = no limit → allow an old key", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, keyType: ed, age: 5 * 365 * day, maxKeyAge: 0,
			wantDecision: allow, wantReason: none, wantUserID: "alice"},
		{name: "under max age → allow", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, keyType: ed, age: 89 * day, maxKeyAge: 90 * day,
			wantDecision: allow, wantReason: none, wantUserID: "alice"},
		{name: "at max age → key_expired", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, keyType: ed, age: 90 * day, maxKeyAge: 90 * day,
			wantDecision: deny, wantReason: expired, wantUserID: "alice"},
		{name: "over max age → key_expired", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, keyType: ed, age: 400 * day, maxKeyAge: 90 * day,
			wantDecision: deny, wantReason: expired, wantUserID: "alice"},
		{name: "sk key passes", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, keyType: sk, wantDecision: allow, wantReason: none, wantUserID: "alice"},
		{name: "revoked sk key → unknown_key", login: "alice", homeAccount: true, boxes: aliceBox,
			registered: true, revoked: true, keyType: sk, wantDecision: deny, wantReason: unknownKey, wantUserID: "alice"},
	}
}

// keySeeder is the one write the table needs to arrange registry state.
type keySeeder interface {
	KeyLookup
	InsertIfAbsent(ctx context.Context, rec KeyRecord) (bool, error)
}

// runDeciderCases runs the table against a key store built by newStore
// (called once per case, so each case starts from an empty registry).
func runDeciderCases(t *testing.T, newStore func(t *testing.T) keySeeder) {
	for _, tc := range deciderCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			home := t.TempDir()
			pub := testKey(t)
			if tc.homeAccount {
				writeHome(t, home, tc.login, pub)
			}
			store := newStore(t)
			rec, err := NewKeyRecord(pub, tc.login, SourceAPI, caseNow.Add(-tc.age))
			if err != nil {
				t.Fatalf("NewKeyRecord: %v", err)
			}
			rec.KeyType = tc.keyType
			if tc.revoked {
				rec.RevokedAt = caseNow.Add(-time.Hour)
			}
			if tc.registered {
				if _, err := store.InsertIfAbsent(ctx, rec); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}

			var boxesErr error
			if tc.boxesErr {
				boxesErr = os.ErrDeadlineExceeded
			}
			d := &SelfHostDecider{
				HomeRoot:      home,
				Boxes:         fakeBoxes{names: tc.boxes, err: boxesErr},
				Collaborators: fakeCollaborators{rows: tc.collaborators},
				Keys:          store,
				MaxKeyAge:     tc.maxKeyAge,
				Now:           func() time.Time { return caseNow },
			}
			cred := &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
				FingerprintSha256: rec.Fingerprint,
				KeyType:           ed,
			}}}
			if tc.noCred {
				cred = &pb.SSHCredential{Kind: &pb.SSHCredential_Certificate{Certificate: &pb.SSHCertificateCredential{
					KeyId: "alice", Serial: 1, CaFingerprintSha256: rec.Fingerprint,
				}}}
			}
			resp, err := d.Decide(ctx, &pb.AuthorizeSSHRequest{Login: tc.login, Credential: cred, ClientIp: "192.0.2.10"})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if resp.GetDecision() != tc.wantDecision || resp.GetDenyReason() != tc.wantReason {
				t.Fatalf("decision = %v/%v, want %v/%v", resp.GetDecision(), resp.GetDenyReason(), tc.wantDecision, tc.wantReason)
			}
			if resp.GetUserId() != tc.wantUserID {
				t.Fatalf("user_id = %q, want %q", resp.GetUserId(), tc.wantUserID)
			}
			if tc.wantDecision == allow {
				if got := resp.GetCacheTtl().AsDuration(); got != SelfHostCacheTTL || SelfHostCacheTTL != 30*time.Second {
					t.Fatalf("cache_ttl = %v, want 30s", got)
				}
			} else if resp.GetCacheTtl() != nil {
				t.Fatalf("a DENY must not carry a positive cache lifetime, got %v", resp.GetCacheTtl())
			}
		})
	}
}
