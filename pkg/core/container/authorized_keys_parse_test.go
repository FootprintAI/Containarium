//go:build !windows

package container

import (
	"strings"
	"testing"
)

// authorized_keys parsing (#1477).
//
// The bug: the parser returned on the FIRST valid key, so recovery restored a
// host account authorizing one key out of however many the container held.
// Every downstream check still looked healthy — account present, pipe built,
// diagnostic clean — and the operator whose key happened to sort second was
// simply refused. Which key survived was decided by file order.
//
// So the property under test is not "parses a key" but "returns ALL of them,
// in order".

const (
	keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator@laptop"
	keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB runner@ci"
	keyC = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCCCCCCCCCCCCCCCCCCCCCCCCCCCCC collaborator@desktop"
)

func TestParseAuthorizedKeysReturnsEveryKey(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			// The regression itself: three keys in, three keys out.
			name:    "multiple keys are all returned in file order",
			content: keyA + "\n" + keyB + "\n" + keyC + "\n",
			want:    []string{keyA, keyB, keyC},
		},
		{
			name:    "single key",
			content: keyA + "\n",
			want:    []string{keyA},
		},
		{
			// Real files carry the sentinel's pushed upstream key under a
			// comment header, plus blank lines. Neither may shift the result.
			name: "comments and blank lines are skipped, not counted",
			content: "# sshpiper sentinel upstream key\n" +
				keyA + "\n" +
				"\n" +
				"   \n" +
				"# another comment\n" +
				keyB + "\n",
			want: []string{keyA, keyB},
		},
		{
			name:    "leading and trailing whitespace is trimmed",
			content: "  " + keyA + "  \n\t" + keyB + "\t\n",
			want:    []string{keyA, keyB},
		},
		{
			name:    "exact duplicates collapse",
			content: keyA + "\n" + keyA + "\n" + keyB + "\n",
			want:    []string{keyA, keyB},
		},
		{
			name:    "garbage lines are ignored but do not stop the scan",
			content: "not-a-key\n" + keyA + "\nalso junk\n" + keyB + "\n",
			want:    []string{keyA, keyB},
		},
		{
			// A malformed FIRST line used to be harmless only by luck; the
			// scan must continue past it rather than yielding nothing.
			name:    "invalid first line does not suppress later valid keys",
			content: "ssh-ed25519\n" + keyB + "\n",
			want:    []string{keyB},
		},
		{
			name:    "empty file yields nothing",
			content: "",
			want:    nil,
		},
		{
			name:    "comments only yields nothing",
			content: "# just a header\n\n",
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAuthorizedKeys(tc.content)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d keys, want %d\ngot:  %v\nwant: %v", len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("key %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// Every key type the old parser accepted must still be accepted — narrowing
// the set while fixing the count would lock out RSA/ECDSA users.
func TestParseAuthorizedKeysAcceptsEveryKeyType(t *testing.T) {
	for _, prefix := range sshKeyPrefixes {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			line := prefix + "AAAAB3NzaC1kc3MAAACBAexample user@host"
			got := parseAuthorizedKeys(line + "\n")
			if len(got) != 1 || got[0] != line {
				t.Errorf("parseAuthorizedKeys(%q) = %v, want exactly [%q]", line, got, line)
			}
		})
	}
}

// The whole line is the dedup key, so identical key material under two
// different comments is kept twice. Deliberate: the parser cannot distinguish
// an intentional re-listing from an accident, and keeping one key too many
// costs nothing while dropping one removes somebody's access.
func TestParseAuthorizedKeysKeepsSameMaterialUnderDifferentComments(t *testing.T) {
	a := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice@one"
	b := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice@two"

	got := parseAuthorizedKeys(a + "\n" + b + "\n")
	if len(got) != 2 {
		t.Errorf("got %d keys, want 2 — differing comments must not be treated as duplicates", len(got))
	}
}
