package sshauthz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileHolders(t *testing.T) {
	home := t.TempDir()
	shared, solo := testKey(t), testKey(t)
	write := func(user string, lines ...string) {
		dir := filepath.Join(home, user, ".ssh")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "# platform\n" + SentinelKeyMarker + "\n" + shared + "\n" // sentinel block is never a holding
		for _, l := range lines {
			body += l + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("alice", shared, solo)
	write("bob", shared)
	write("carol")

	fp := func(pub string) string { return mustRecordT(t, pub).Fingerprint }
	h := FileHolders{HomeRoot: home}
	for _, tc := range []struct {
		name, key, exclude string
		want               bool
	}{
		{"bob holds shared, asked as alice", shared, "alice", true},
		{"alice holds shared, asked as bob", shared, "bob", true},
		{"only alice holds solo", solo, "alice", false},
		{"alice holds solo, asked as bob", solo, "bob", true},
		{"nobody holds an unknown key", testKey(t), "alice", false},
		{"collaborator account is another account", shared, "alice-container-bob", true},
	} {
		got, err := h.OtherAccountHolds(t.Context(), fp(tc.key), tc.exclude)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := (FileHolders{HomeRoot: home + "/missing"}).OtherAccountHolds(t.Context(), fp(solo), "alice"); err == nil {
		t.Error("an unreadable home root must be an error (fail closed), not 'no holder'")
	}
}

func mustRecordT(t *testing.T, pub string) KeyRecord {
	t.Helper()
	rec, err := NewKeyRecord(pub, "probe", SourceAPI, caseNow)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
