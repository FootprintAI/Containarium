package sshconfig

import (
	"strings"
	"testing"
)

func TestRotateIdentity_PreservesHostsAndUnmanagedContent(t *testing.T) {
	before := "Host unrelated\n    IdentityFile ~/.ssh/personal\n\n"
	after := "\nHost elsewhere\n    IdentityFile ~/.ssh/other\n"
	managed := beginMarker + `
Host box
    HostName sentinel.example.com
    User box
    IdentityFile ~/.ssh/old
    IdentitiesOnly yes

Host box-jump
    HostName backend.example.com
    User alice
    IdentitiesOnly yes
` + endMarker + "\n"
	g, err := RotateIdentity(before+managed+after, "/home/alice user/.ssh/new")
	if err != nil {
		t.Fatal(err)
	}
	if g.Count != 2 || !strings.HasPrefix(g.Content, before) || !strings.HasSuffix(g.Content, after) {
		t.Fatalf("host count or unmanaged content changed: %+v", g)
	}
	if strings.Contains(g.Content, "~/.ssh/old") || strings.Count(g.Content, `IdentityFile "/home/alice user/.ssh/new"`) != 2 {
		t.Fatalf("new identity not selected for both SSH hops:\n%s", g.Content)
	}
	for _, routing := range []string{"HostName sentinel.example.com", "HostName backend.example.com", "User alice", "User box"} {
		if !strings.Contains(g.Content, routing) {
			t.Errorf("routing lost: %s", routing)
		}
	}
}

func TestRotateIdentity_RejectsUnmanagedOrEmptyConfiguration(t *testing.T) {
	for _, config := range []string{
		"", "Host personal\n", beginMarker + "\n" + endMarker + "\n",
		beginMarker + "\nHost box\n", endMarker + "\n" + beginMarker + "\nHost box\n",
	} {
		if _, err := RotateIdentity(config, "/home/alice/.ssh/new"); err == nil {
			t.Errorf("accepted unsafe or empty configuration: %q", config)
		}
	}
}

func TestRotateIdentity_RejectsInvalidIdentityPath(t *testing.T) {
	config := beginMarker + "\nHost box\n" + endMarker + "\n"
	for _, path := range []string{"", "key\nHost *", "key\rIdentityFile x", "key\x00"} {
		if _, err := RotateIdentity(config, path); err == nil {
			t.Errorf("accepted invalid identity path %q", path)
		}
	}
}
