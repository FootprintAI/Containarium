package sshauthz

import (
	"sort"
	"strings"
	"testing"
)

// fixtureHome lays out a /home tree with an owner, a collaborator, the
// sentinel's marked block, comments, blank lines and an unparseable line.
// It returns the root and the public keys a backfill must register.
func fixtureHome(t *testing.T) (root string, want map[string]string) {
	t.Helper()
	root = t.TempDir()
	aliceA, aliceB, bob, sentinel := testKey(t), testKey(t), testKey(t), testKey(t)
	writeHome(t, root, "alice", strings.Join([]string{
		"# managed by containarium",
		strings.TrimSpace(aliceA),
		"",
		`no-pty ` + strings.TrimSpace(aliceB),
		"",
		SentinelKeyMarker,
		strings.TrimSpace(sentinel),
		"",
	}, "\n"))
	writeHome(t, root, "alice-container-bob", strings.TrimSpace(bob)+"\nnot-a-key garbage\n")
	writeHome(t, root, "empty", "")
	return root, map[string]string{
		strings.TrimSpace(aliceA): "alice",
		strings.TrimSpace(aliceB): "alice",
		strings.TrimSpace(bob):    "alice-container-bob",
	}
}

func TestScanAuthorizedKeys(t *testing.T) {
	root, want := fixtureHome(t)
	recs, err := ScanAuthorizedKeys(root, caseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(recs), len(want), recs)
	}
	var users []string
	for _, r := range recs {
		username, ok := want[r.PublicKey]
		if !ok {
			t.Fatalf("unexpected key registered (sentinel key or garbage leaked?): %+v", r)
		}
		if r.Username != username || r.UserID != UserIDForLogin(username) || r.Source != SourceBackfill ||
			!r.CreatedAt.Equal(caseNow) || !r.RevokedAt.IsZero() {
			t.Fatalf("bad record %+v", r)
		}
		users = append(users, r.UserID)
	}
	sort.Strings(users)
	if strings.Join(users, ",") != "alice,alice,bob" {
		t.Fatalf("user ids = %v", users)
	}
}

func TestScanAuthorizedKeys_MissingRoot(t *testing.T) {
	if _, err := ScanAuthorizedKeys(t.TempDir()+"/nope", caseNow); err == nil {
		t.Fatal("a missing home root must be an error, not an empty backfill")
	}
}

func TestBackfill_TwiceAddsNothing_InMemory(t *testing.T) {
	root, want := fixtureHome(t)
	store := &memKeys{rows: map[string]KeyRecord{}}
	n, err := Backfill(t.Context(), store, root, caseNow)
	if err != nil || n != len(want) {
		t.Fatalf("first backfill = %d, %v; want %d", n, err, len(want))
	}
	n, err = Backfill(t.Context(), store, root, caseNow)
	if err != nil || n != 0 {
		t.Fatalf("second backfill = %d, %v; want 0", n, err)
	}
}
