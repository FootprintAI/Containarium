package container

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const replaceTestKey3 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq6JPuM6JlU+5s2m0oWz8aUo6d9lBn3pq1tH0v3b5jK test3"

// sentinelBlock is how the sentinel's upstream key sits in a box's file.
const sentinelBlock = SentinelKeyMarker + "\n" + "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlatformSentinelKeyMaterial000000000000000 sentinel\n"

func replaceFixture(t *testing.T, content string) (user, path string) {
	t.Helper()
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })
	user = "boxuser"
	path = filepath.Join(tmp, user, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return user, path
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReplaceAuthorizedKeys_SetThenShrink(t *testing.T) {
	user, path := replaceFixture(t, "")
	if _, err := ReplaceAuthorizedKeys(user, []string{validTestKey1, validTestKey2}, nil); err != nil {
		t.Fatal(err)
	}
	removed, err := ReplaceAuthorizedKeys(user, []string{validTestKey2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if strings.Contains(got, validTestKey1) || !strings.Contains(got, validTestKey2) {
		t.Fatalf("want only key2, got %q", got)
	}
	if !reflect.DeepEqual(removed, []string{validTestKey1}) {
		t.Fatalf("removed = %v, want [key1]", removed)
	}
}

func TestReplaceAuthorizedKeys_EmptyKeepsPlatformKey(t *testing.T) {
	user, path := replaceFixture(t, validTestKey1+"\n"+validTestKey2+"\n\n"+sentinelBlock)
	removed, err := ReplaceAuthorizedKeys(user, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if strings.Contains(got, validTestKey1) || strings.Contains(got, validTestKey2) {
		t.Fatalf("caller keys survived: %q", got)
	}
	if !strings.Contains(got, sentinelBlock) {
		t.Fatalf("platform key lost: %q", got)
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %v, want 2 caller keys (never the platform key)", removed)
	}
}

func TestReplaceAuthorizedKeys_Idempotent(t *testing.T) {
	user, path := replaceFixture(t, validTestKey3Seed()+"\n\n"+sentinelBlock)
	want := []string{validTestKey1, validTestKey2, validTestKey1} // duplicate collapses
	if _, err := ReplaceAuthorizedKeys(user, want, nil); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, path)
	removed, err := ReplaceAuthorizedKeys(user, want, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second := readFile(t, path); second != first {
		t.Fatalf("second call changed file:\n%q\n%q", first, second)
	}
	if len(removed) != 0 {
		t.Fatalf("second call removed %v", removed)
	}
	if strings.Count(first, validTestKey1) != 1 {
		t.Fatalf("duplicate not collapsed: %q", first)
	}
}

func validTestKey3Seed() string { return replaceTestKey3 }

func TestReplaceAuthorizedKeys_InvalidKeyChangesNothing(t *testing.T) {
	orig := validTestKey1 + "\n\n" + sentinelBlock
	user, path := replaceFixture(t, orig)
	cases := map[string][]string{
		"malformed":  {validTestKey2, "ssh-ed25519 not-base64"},
		"options":    {validTestKey2, `command="/bin/sh" ` + validTestKey3Seed()},
		"from":       {`from="10.0.0.1" ` + validTestKey2},
		"multi-line": {validTestKey2 + "\n" + validTestKey3Seed()},
		"empty":      {validTestKey2, "   "},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplaceAuthorizedKeys(user, keys, nil); err == nil {
				t.Fatal("want error")
			}
			if got := readFile(t, path); got != orig {
				t.Fatalf("file changed on rejected call: %q", got)
			}
		})
	}
}

func TestValidateStrictSSHPublicKey(t *testing.T) {
	if err := ValidateStrictSSHPublicKey(validTestKey1); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	for _, bad := range []string{
		`no-pty ` + validTestKey1,
		validTestKey1 + "\r\n" + validTestKey2,
		SentinelKeyMarker,
		"",
	} {
		if err := ValidateStrictSSHPublicKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func genKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	if comment != "" {
		line += " " + comment
	}
	return line
}

// A failing beforeWrite (registry revoke) leaves the file untouched, and a
// retry still sees the same keys to drop.
func TestReplaceAuthorizedKeys_HookFailureLeavesFileAndRetrySeesKeys(t *testing.T) {
	a, b := genKey(t, "a"), genKey(t, "b")
	orig := a + "\n" + b + "\n"
	user, path := replaceFixture(t, orig)

	_, err := ReplaceAuthorizedKeys(user, []string{b}, func(removed []string) error {
		if len(removed) != 1 || removed[0] != a {
			t.Errorf("hook removed = %v", removed)
		}
		return fmt.Errorf("registry down")
	})
	if err == nil {
		t.Fatal("hook error not returned")
	}
	if got := readFile(t, path); got != orig {
		t.Fatalf("file changed after failed hook: %q", got)
	}
	var seen []string
	if _, err := ReplaceAuthorizedKeys(user, []string{b}, func(r []string) error { seen = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != a || strings.Contains(readFile(t, path), a) {
		t.Fatalf("retry: seen=%v file=%q", seen, readFile(t, path))
	}
}

// Replace and Add share one lock: neither may be lost. Run with -race.
func TestReplaceAuthorizedKeys_ConcurrentAddAndSetLoseNothing(t *testing.T) {
	for round := 0; round < 30; round++ {
		keep, added := genKey(t, "keep"), genKey(t, "added")
		user, path := replaceFixture(t, "")
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = AddAuthorizedKey(user, added) }()
		go func() { defer wg.Done(); _, _ = ReplaceAuthorizedKeys(user, []string{keep}, nil) }()
		wg.Wait()
		got := readFile(t, path)
		if !strings.Contains(got, keep) {
			t.Fatalf("round %d: Set's key lost: %q", round, got)
		}
		// Add either ran before Set (then Set legitimately dropped it) or
		// after (then it must be present). A torn file contains neither
		// whole line or a partial one.
		for _, l := range strings.Split(strings.TrimSpace(got), "\n") {
			if l != keep && l != added {
				t.Fatalf("round %d: torn line %q in %q", round, l, got)
			}
		}
		if err := AddAuthorizedKey(user, added); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(readFile(t, path), added) {
			t.Fatalf("round %d: Add lost", round)
		}
	}
}

// Concurrent Adds and a Remove interleaved with Sets must never corrupt.
func TestReplaceAuthorizedKeys_ConcurrentAddsAllSurvive(t *testing.T) {
	user, path := replaceFixture(t, "")
	var wg sync.WaitGroup
	keys := make([]string, 40)
	for i := range keys {
		keys[i] = genKey(t, "")
		wg.Add(1)
		go func(k string) { defer wg.Done(); _ = AddAuthorizedKey(user, k) }(keys[i])
	}
	wg.Wait()
	got := readFile(t, path)
	for _, k := range keys {
		if !strings.Contains(got, k) {
			t.Fatalf("concurrent Add lost %q", k)
		}
	}
}

func TestReplaceAuthorizedKeys_WritesRegeneratedCanonicalLine(t *testing.T) {
	user, path := replaceFixture(t, "")
	base := genKey(t, "")
	for name, comment := range map[string]string{
		"command-subst": "$(touch_x)",
		"marker":        "# sshpiper sentinel upstream key",
		"unicode-sep":   "a\u2028b\u0085c",
		"control":       "a\x07b",
	} {
		if _, err := ReplaceAuthorizedKeys(user, []string{base + " " + comment}, nil); err != nil {
			// A key whose comment holds a control char may be rejected;
			// that is also safe.
			continue
		}
		got := readFile(t, path)
		if strings.ContainsAny(got, "\u2028\u0085\x07$()#") {
			t.Fatalf("%s: unsafe bytes survived: %q", name, got)
		}
		if lines := strings.Split(strings.TrimSpace(got), "\n"); len(lines) != 1 {
			t.Fatalf("%s: %d lines: %q", name, len(lines), got)
		}
	}
	// A key with no comment, and a plain comment, keep their form.
	if _, err := ReplaceAuthorizedKeys(user, []string{base, genKey(t, "ci@host")}, nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); !strings.HasPrefix(got, base+"\n") || !strings.Contains(got, " ci@host\n") {
		t.Fatalf("canonical form lost: %q", got)
	}
}

func TestReplaceAuthorizedKeys_Bounds(t *testing.T) {
	user, path := replaceFixture(t, "")
	var many []string
	for i := 0; i <= MaxAuthorizedKeys; i++ {
		many = append(many, genKey(t, ""))
	}
	if _, err := ReplaceAuthorizedKeys(user, many, nil); err == nil {
		t.Fatal("over-count accepted")
	}
	if _, err := ReplaceAuthorizedKeys(user, []string{genKey(t, strings.Repeat("x", MaxAuthorizedKeyBytes))}, nil); err == nil {
		t.Fatal("oversize key accepted")
	}
	if _, err := ReplaceAuthorizedKeys(user, many[:MaxAuthorizedKeys], nil); err != nil {
		t.Fatalf("exactly the limit rejected: %v", err)
	}
	if got := readFile(t, path); strings.Count(got, "\n") != MaxAuthorizedKeys {
		t.Fatalf("lines = %d", strings.Count(got, "\n"))
	}
}

// A legacy file with garbage lines and an options-bearing line: the rewrite
// drops them (reporting only the parseable key as removed) and keeps the
// sentinel block.
func TestReplaceAuthorizedKeys_LegacyFileGarbageAndOptions(t *testing.T) {
	legacy, keep := genKey(t, "legacy"), genKey(t, "keep")
	sent := genKey(t, "sentinel")
	user, path := replaceFixture(t, "garbage line\n# a comment\n\x00\x01junk\n"+
		`command="/bin/true",no-pty `+legacy+"\n"+keep+"\n\n"+SentinelKeyMarker+"\n"+sent+"\n")
	removed, err := ReplaceAuthorizedKeys(user, []string{keep}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || !strings.Contains(removed[0], legacy) {
		t.Fatalf("removed = %v", removed)
	}
	want := keep + "\n\n" + SentinelKeyMarker + "\n" + sent + "\n"
	if got := readFile(t, path); got != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

// Submitting the sentinel's own key as a caller key neither duplicates it,
// nor ever reports it as removed (it would be revoked in the registry).
func TestReplaceAuthorizedKeys_SentinelKeySubmittedAsCallerKey(t *testing.T) {
	sent := genKey(t, "sentinel")
	user, path := replaceFixture(t, SentinelKeyMarker+"\n"+sent+"\n")
	if _, err := ReplaceAuthorizedKeys(user, []string{sent}, nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); strings.Count(got, sent) != 1 || !strings.Contains(got, SentinelKeyMarker+"\n"+sent) {
		t.Fatalf("file = %q", got)
	}
	// A legacy file that also holds the sentinel key as a plain caller line.
	if err := os.WriteFile(path, []byte(sent+"\n\n"+SentinelKeyMarker+"\n"+sent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := ReplaceAuthorizedKeys(user, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 || strings.Count(readFile(t, path), sent) != 1 {
		t.Fatalf("sentinel key removed/reported: %v %q", removed, readFile(t, path))
	}
}

// An Add that starts while a Replace is mid-flight (inside beforeWrite) must
// wait for it and land afterwards, not be overwritten by the rename.
func TestReplaceAuthorizedKeys_HoldsLockAgainstConcurrentAdd(t *testing.T) {
	keep, added := genKey(t, "keep"), genKey(t, "added")
	user, path := replaceFixture(t, "")
	done := make(chan struct{})
	_, err := ReplaceAuthorizedKeys(user, []string{keep}, func([]string) error {
		go func() { defer close(done); _ = AddAuthorizedKey(user, added) }()
		select {
		case <-done:
			t.Error("Add completed while Replace held the lock")
		case <-time.After(200 * time.Millisecond):
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	got := readFile(t, path)
	if !strings.Contains(got, keep) || !strings.Contains(got, added) {
		t.Fatalf("lost an update: %q", got)
	}
}
