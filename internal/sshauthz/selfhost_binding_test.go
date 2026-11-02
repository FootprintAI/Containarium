package sshauthz

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A key registered for one account must not authorize a login to another
// account whose own authorized_keys does not hold it.
func TestSelfHostDecider_KeyNotHeldByLoginIsDenied(t *testing.T) {
	home := t.TempDir()
	aliceKey, bobKey := testKey(t), testKey(t)
	writeHome(t, home, "alice", aliceKey)
	writeHome(t, home, "bob", bobKey)

	store := &memKeys{rows: map[string]KeyRecord{}}
	for user, k := range map[string]string{"alice": aliceKey, "bob": bobKey} {
		rec, err := NewKeyRecord(k, user, SourceAPI, caseNow)
		if err != nil {
			t.Fatal(err)
		}
		store.rows[rec.Fingerprint] = rec
	}
	bobRec, _ := NewKeyRecord(bobKey, "bob", SourceAPI, caseNow)

	d := &SelfHostDecider{
		HomeRoot: home,
		Boxes:    fakeBoxes{names: map[string]bool{"alice-container": true, "bob-container": true}},
		Keys:     store,
		Now:      func() time.Time { return caseNow },
	}
	decide := func(login string) *pb.AuthorizeSSHResponse {
		resp, err := d.Decide(context.Background(), &pb.AuthorizeSSHRequest{
			Login: login,
			Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
				FingerprintSha256: bobRec.Fingerprint,
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if got := decide("bob").GetDecision(); got != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
		t.Fatalf("bob's key as bob: got %v, want ALLOW", got)
	}
	resp := decide("alice")
	if resp.GetDecision() != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY ||
		resp.GetDenyReason() != pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY {
		t.Fatalf("bob's key as alice: got %v/%v, want DENY/UNKNOWN_KEY", resp.GetDecision(), resp.GetDenyReason())
	}
}

// The binding check must cope with the shapes real authorized_keys files have.
func TestJumpAccountHoldsKey_FileShapes(t *testing.T) {
	good := testKey(t)
	other := testKey(t)
	rec, err := NewKeyRecord(good, "x", SourceAPI, caseNow)
	if err != nil {
		t.Fatal(err)
	}
	fp := rec.Fingerprint
	trim := func(k string) string { return strings.TrimSpace(k) }
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"plain", good, true},
		{"comment and blank lines first", "# note\n\n" + good, true},
		{"malformed line before the key", "this is not a key\n" + good, true},
		{"other key before the key", other + good, true},
		{"with options", `from="10.0.0.1",no-pty ` + trim(good) + "\n", true},
		{"only another key", other, false},
		{"cert-authority entry for the same key", "cert-authority " + trim(good) + "\n", false},
		{"empty file", "", false},
	}
	for _, c := range cases {
		home := t.TempDir()
		writeHome(t, home, "alice", c.content)
		d := &SelfHostDecider{HomeRoot: home}
		if got := d.jumpAccountHoldsKey("alice", fp); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	d := &SelfHostDecider{HomeRoot: t.TempDir()}
	if d.jumpAccountHoldsKey("ghost", fp) {
		t.Error("login with no authorized_keys file must be denied")
	}
}

// A collaborator login has its own account; the owner's key must not carry over.
func TestSelfHostDecider_CollaboratorKeyBinding(t *testing.T) {
	home := t.TempDir()
	ownerKey, collabKey := testKey(t), testKey(t)
	writeHome(t, home, "alice", ownerKey)
	writeHome(t, home, "alice-container-bob", collabKey)
	d := &SelfHostDecider{HomeRoot: home}
	ownerRec, _ := NewKeyRecord(ownerKey, "alice", SourceAPI, caseNow)
	collabRec, _ := NewKeyRecord(collabKey, "alice-container-bob", SourceCollaborator, caseNow)
	if !d.jumpAccountHoldsKey("alice-container-bob", collabRec.Fingerprint) {
		t.Error("collaborator's own key should be held")
	}
	if d.jumpAccountHoldsKey("alice-container-bob", ownerRec.Fingerprint) {
		t.Error("owner's key must not be held by the collaborator account")
	}
}
