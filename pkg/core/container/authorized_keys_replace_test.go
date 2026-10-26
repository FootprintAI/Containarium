package container

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
	if _, err := ReplaceAuthorizedKeys(user, []string{validTestKey1, validTestKey2}); err != nil {
		t.Fatal(err)
	}
	removed, err := ReplaceAuthorizedKeys(user, []string{validTestKey2})
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
	removed, err := ReplaceAuthorizedKeys(user, nil)
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
	if _, err := ReplaceAuthorizedKeys(user, want); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, path)
	removed, err := ReplaceAuthorizedKeys(user, want)
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
			if _, err := ReplaceAuthorizedKeys(user, keys); err == nil {
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
