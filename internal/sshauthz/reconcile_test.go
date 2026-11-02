package sshauthz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3330, decision Q14 on #3335: while the ssh_keys registry is absent (a
// degraded start), RemoveSSHKey and the other revoke paths are no-ops on it,
// so a key removed from authorized_keys in that window keeps an active row.
// The backfill only adds. These tests first pin whether the decider's /home
// check already makes such a row harmless (it does not), then cover
// Reconcile, which revokes the rows no account holds.

// reconcileKeys is an in-memory registry for the reconcile unit tests.
// Revoke marks the row revoked, the way PGKeyStore does for an owner with no
// other holder; the ownership and holder rules themselves are tested
// against Postgres.
type reconcileKeys struct {
	rows      map[string]KeyRecord
	listErr   error
	revokeErr map[string]error
	revoked   []string
	// onList runs once inside ActiveRecords, before the rows are read: a
	// concurrent API write that lands while Reconcile is running.
	onList func()
}

func newReconcileKeys() *reconcileKeys {
	return &reconcileKeys{rows: map[string]KeyRecord{}, revokeErr: map[string]error{}}
}

func (m *reconcileKeys) Lookup(_ context.Context, fingerprint string) (KeyRecord, error) {
	rec, ok := m.rows[fingerprint]
	if !ok {
		return KeyRecord{}, ErrKeyNotFound
	}
	return rec, nil
}

func (m *reconcileKeys) ActiveRecords(context.Context) ([]KeyRecord, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.onList != nil {
		m.onList()
		m.onList = nil
	}
	var out []KeyRecord
	for _, r := range m.rows {
		if r.RevokedAt.IsZero() {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, nil
}

func (m *reconcileKeys) Revoke(_ context.Context, rec KeyRecord, at time.Time) error {
	if err := m.revokeErr[rec.Fingerprint]; err != nil {
		return err
	}
	cur := m.rows[rec.Fingerprint]
	cur.RevokedAt = at
	m.rows[rec.Fingerprint] = cur
	m.revoked = append(m.revoked, rec.Fingerprint)
	return nil
}

// seed registers pub to username as an active row.
func (m *reconcileKeys) seed(t *testing.T, pub, username string) KeyRecord {
	t.Helper()
	rec, err := NewKeyRecord(pub, username, SourceAPI, caseNow.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	m.rows[rec.Fingerprint] = rec
	return rec
}

func aliceDecider(home string, keys KeyLookup) *SelfHostDecider {
	return &SelfHostDecider{HomeRoot: home, Boxes: fakeBoxes{names: aliceBox}, Keys: keys, Now: func() time.Time { return caseNow }}
}

func decideKey(t *testing.T, d *SelfHostDecider, login string, rec KeyRecord) *pb.AuthorizeSSHResponse {
	t.Helper()
	resp, err := d.Decide(context.Background(), &pb.AuthorizeSSHRequest{
		Login: login,
		Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
			FingerprintSha256: rec.Fingerprint, KeyType: rec.KeyType,
		}}},
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return resp
}

// Q14, first half: the decider's /home check is that the login's account
// HAS a non-empty authorized_keys, not that it holds the offered key. So a
// key removed during the window, whose row is still active, is still
// allowed while the account keeps any other key. The check does not make
// the stale row harmless; that is why the late install reconciles.
func TestReconcile_DeciderAllowsAStaleRowWithoutIt(t *testing.T) {
	home := t.TempDir()
	keys := newReconcileKeys()
	kept, removed := testKey(t), testKey(t)
	keys.seed(t, kept, "alice")
	stale := keys.seed(t, removed, "alice")
	writeHome(t, home, "alice", kept) // `removed` was dropped while the registry was absent

	resp := decideKey(t, aliceDecider(home, keys), "alice", stale)
	if resp.GetDecision() != allow {
		t.Fatalf("stale row decision = %v (%v); this test pins that the /home check alone does NOT refuse it — if the decider now checks the offered key, revisit Q14",
			resp.GetDecision(), resp.GetDenyReason())
	}
}

// Q14, second half: Reconcile revokes every active row whose key no
// account holds, and only those. Afterwards the stale key is refused.
func TestReconcile_RevokesRowsNoAccountHolds(t *testing.T) {
	home := t.TempDir()
	keys := newReconcileKeys()
	kept, removed, otherHeld, gone := testKey(t), testKey(t), testKey(t), testKey(t)
	keptRec := keys.seed(t, kept, "alice")
	stale := keys.seed(t, removed, "alice")
	// A row alice registered first but only bob holds now: held, so kept.
	sharedRec := keys.seed(t, otherHeld, "alice")
	// A released row (#3217) no one holds any more.
	released := keys.seed(t, gone, "carol")
	released.ReleasedAt = caseNow.Add(-time.Minute)
	keys.rows[released.Fingerprint] = released
	// An already revoked row is not touched again.
	oldRevoked := keys.seed(t, testKey(t), "alice")
	oldRevoked.RevokedAt = caseNow.Add(-48 * time.Hour)
	keys.rows[oldRevoked.Fingerprint] = oldRevoked

	writeHome(t, home, "alice", kept)
	writeHome(t, home, "bob", otherHeld)

	got, err := Reconcile(context.Background(), keys, home, caseNow)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got.Revoked != 2 || got.Unresolved != 0 {
		t.Errorf("Reconcile = %+v, want 2 revoked, 0 unresolved", got)
	}
	want := map[string]bool{stale.Fingerprint: true, released.Fingerprint: true}
	if len(keys.revoked) != len(want) {
		t.Fatalf("revoked %v, want exactly the stale and released rows", keys.revoked)
	}
	for _, fp := range keys.revoked {
		if !want[fp] {
			t.Errorf("revoked %s, which an account still holds or was already revoked", fp)
		}
	}
	for _, rec := range []KeyRecord{keptRec, sharedRec} {
		if !keys.rows[rec.Fingerprint].RevokedAt.IsZero() {
			t.Errorf("%s revoked although an account holds it", rec.Fingerprint)
		}
	}
	if at := keys.rows[oldRevoked.Fingerprint].RevokedAt; !at.Equal(caseNow.Add(-48 * time.Hour)) {
		t.Errorf("already revoked row's revoked_at = %v, want it unchanged", at)
	}

	d := aliceDecider(home, keys)
	if resp := decideKey(t, d, "alice", stale); resp.GetDecision() != deny || resp.GetDenyReason() != unknownKey {
		t.Errorf("stale key after Reconcile = %v/%v, want DENY UNKNOWN_KEY", resp.GetDecision(), resp.GetDenyReason())
	}
	if resp := decideKey(t, d, "alice", keptRec); resp.GetDecision() != allow {
		t.Errorf("held key after Reconcile = %v/%v, want ALLOW", resp.GetDecision(), resp.GetDenyReason())
	}

	// Idempotent: a second run finds nothing to revoke.
	again, err := Reconcile(context.Background(), keys, home, caseNow)
	if err != nil || again.Revoked != 0 {
		t.Errorf("second Reconcile = %+v, %v; want nothing revoked", again, err)
	}
}

// A key added through the API while Reconcile runs (file written, then
// registered) must not be revoked. The API writes the file before it
// registers the row, so Reconcile reads the rows first and scans /home
// after: any row it sees already has its file. Scanning first would miss
// the file, see the row, and revoke a key its account holds. The revoke-time
// holder check would not save it, because it excludes the row's own account.
func TestReconcile_KeyAddedDuringReconcileIsNotRevoked(t *testing.T) {
	home := t.TempDir()
	keys := newReconcileKeys()
	kept := testKey(t)
	keys.seed(t, kept, "alice")
	writeHome(t, home, "alice", kept)

	added := testKey(t)
	var addedRec KeyRecord
	keys.onList = func() {
		writeHome(t, home, "alice", kept+added) // AddSSHKey writes the file...
		addedRec = keys.seed(t, added, "alice") // ...then registers the key
	}

	got, err := Reconcile(context.Background(), keys, home, caseNow)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !keys.rows[addedRec.Fingerprint].RevokedAt.IsZero() {
		t.Fatalf("key added during Reconcile was revoked although alice holds it (Reconcile = %+v)", got)
	}
	if got.Revoked != 0 {
		t.Errorf("Reconcile = %+v, want nothing revoked", got)
	}
}

// An account whose authorized_keys cannot be read might hold any key, so no
// row is revoked on its account's say-so (the #3241 rule for revokes): the
// rows are counted as unresolved and the run still succeeds, so one bad home
// does not keep the registry off for everyone.
func TestReconcile_UnreadableAccountRevokesNothing(t *testing.T) {
	home := t.TempDir()
	keys := newReconcileKeys()
	stale := keys.seed(t, testKey(t), "alice")
	writeHome(t, home, "alice", testKey(t))
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, "mallory")); err != nil {
		t.Fatal(err)
	}

	got, err := Reconcile(context.Background(), keys, home, caseNow)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got.Revoked != 0 || got.Unresolved != 1 {
		t.Errorf("Reconcile = %+v, want 0 revoked, 1 unresolved", got)
	}
	if !keys.rows[stale.Fingerprint].RevokedAt.IsZero() {
		t.Error("row revoked while an unreadable account could hold its key")
	}
}

// A holder that appears between the scan and the revoke (the store's own
// holder check refuses) leaves the row and is not an error.
func TestReconcile_HolderFoundAtRevokeIsUnresolved(t *testing.T) {
	home := t.TempDir()
	keys := newReconcileKeys()
	a := keys.seed(t, testKey(t), "alice")
	b := keys.seed(t, testKey(t), "alice")
	keys.revokeErr[a.Fingerprint] = ErrKeyHeldByOtherAccount
	keys.revokeErr[b.Fingerprint] = ErrHolderUnknown

	got, err := Reconcile(context.Background(), keys, home, caseNow)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got.Revoked != 0 || got.Unresolved != 2 {
		t.Errorf("Reconcile = %+v, want 0 revoked, 2 unresolved", got)
	}
}

// Failures that leave the outcome unknown are returned, so the late install
// retries: the registry cannot be listed, a revoke fails for another reason,
// or the home root cannot be read.
func TestReconcile_FailuresAreReturned(t *testing.T) {
	dbErr := errors.New("connection reset")

	keys := newReconcileKeys()
	keys.listErr = dbErr
	if _, err := Reconcile(context.Background(), keys, t.TempDir(), caseNow); !errors.Is(err, dbErr) {
		t.Errorf("list failure: Reconcile err = %v, want %v", err, dbErr)
	}

	keys = newReconcileKeys()
	rec := keys.seed(t, testKey(t), "alice")
	keys.revokeErr[rec.Fingerprint] = dbErr
	if _, err := Reconcile(context.Background(), keys, t.TempDir(), caseNow); !errors.Is(err, dbErr) {
		t.Errorf("revoke failure: Reconcile err = %v, want %v", err, dbErr)
	}

	keys = newReconcileKeys()
	keys.seed(t, testKey(t), "alice")
	if _, err := Reconcile(context.Background(), keys, filepath.Join(t.TempDir(), "missing"), caseNow); err == nil {
		t.Error("unreadable home root: Reconcile err = nil, want an error")
	}
	if len(keys.revoked) != 0 {
		t.Errorf("revoked %v with an unreadable home root", keys.revoked)
	}
}
