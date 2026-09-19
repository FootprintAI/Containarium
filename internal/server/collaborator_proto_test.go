package server

import (
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/collaborator"
)

// TestSplitSSHPublicKeys pins #1144's decode half: the stored value is a
// newline-joined blob (#369's AddCollaborator writes strings.Join(keys, "\n")
// into the one TEXT column) — this must recover the original list, and never
// choke on the single-key case that predates #369.
func TestSplitSSHPublicKeys(t *testing.T) {
	cases := []struct {
		name string
		blob string
		want []string
	}{
		{"empty", "", nil},
		{"single key, no newline", "ssh-ed25519 AAAAsingle", []string{"ssh-ed25519 AAAAsingle"}},
		{"two keys", "ssh-ed25519 AAAAlaptop\nssh-ed25519 AAAAdesktop", []string{"ssh-ed25519 AAAAlaptop", "ssh-ed25519 AAAAdesktop"}},
		{"blank lines dropped", "ssh-ed25519 AAAAone\n\nssh-ed25519 AAAAtwo\n", []string{"ssh-ed25519 AAAAone", "ssh-ed25519 AAAAtwo"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitSSHPublicKeys(tc.blob)
			if len(got) != len(tc.want) {
				t.Fatalf("splitSSHPublicKeys(%q) = %v, want %v", tc.blob, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("splitSSHPublicKeys(%q)[%d] = %q, want %q", tc.blob, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestCollaboratorToProto is #1144's core fix: the response proto must carry
// every authorized key as ssh_public_keys, while the deprecated ssh_public_key
// scalar becomes a REAL single key (the first one) instead of the whole
// newline-joined blob it silently was before this field existed.
func TestCollaboratorToProto(t *testing.T) {
	now := time.Now()
	c := &collaborator.Collaborator{
		ID:                   "c1",
		ContainerName:        "alice-container",
		OwnerUsername:        "alice",
		CollaboratorUsername: "bob",
		AccountName:          "alice-container-bob",
		SSHPublicKey:         "ssh-ed25519 AAAAlaptop\nssh-ed25519 AAAAdesktop",
		CreatedAt:            now,
		CreatedBy:            "alice",
		HasSudo:              true,
		HasContainerRuntime:  false,
	}

	got := collaboratorToProto(c)

	if got.GetSshPublicKey() != "ssh-ed25519 AAAAlaptop" {
		t.Errorf("SshPublicKey = %q, want just the first key, not the joined blob", got.GetSshPublicKey())
	}
	want := []string{"ssh-ed25519 AAAAlaptop", "ssh-ed25519 AAAAdesktop"}
	if len(got.GetSshPublicKeys()) != len(want) {
		t.Fatalf("SshPublicKeys = %v, want %v", got.GetSshPublicKeys(), want)
	}
	for i, k := range want {
		if got.GetSshPublicKeys()[i] != k {
			t.Errorf("SshPublicKeys[%d] = %q, want %q", i, got.GetSshPublicKeys()[i], k)
		}
	}
	// The rest of the mapping must still round-trip untouched.
	if got.GetId() != "c1" || got.GetOwnerUsername() != "alice" || got.GetCollaboratorUsername() != "bob" ||
		got.GetAccountName() != "alice-container-bob" || !got.GetHasSudo() || got.GetHasContainerRuntime() {
		t.Errorf("unrelated fields changed: %+v", got)
	}
	if got.GetAddedAt() != now.Unix() {
		t.Errorf("AddedAt = %d, want %d", got.GetAddedAt(), now.Unix())
	}
}

// TestCollaboratorToProto_SingleKey is the pre-#369 / single-key case: a
// collaborator with exactly one key must not regress — scalar and the sole
// element of the repeated field agree.
func TestCollaboratorToProto_SingleKey(t *testing.T) {
	c := &collaborator.Collaborator{ID: "c2", SSHPublicKey: "ssh-ed25519 AAAAonly"}
	got := collaboratorToProto(c)
	if got.GetSshPublicKey() != "ssh-ed25519 AAAAonly" {
		t.Errorf("SshPublicKey = %q", got.GetSshPublicKey())
	}
	if len(got.GetSshPublicKeys()) != 1 || got.GetSshPublicKeys()[0] != "ssh-ed25519 AAAAonly" {
		t.Errorf("SshPublicKeys = %v, want [ssh-ed25519 AAAAonly]", got.GetSshPublicKeys())
	}
}
