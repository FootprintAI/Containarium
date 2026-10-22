package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/credentials"
)

func seedServerCreds(t *testing.T, servers ...string) {
	t.Helper()
	path, err := credentials.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	cf := credentials.NewCredentialsFile()
	for _, s := range servers {
		cf.Set(s, credentials.ServerCreds{Token: "tok-" + s})
	}
	if err := credentials.Save(path, cf); err != nil {
		t.Fatal(err)
	}
}

// #2238: `--server host` must resolve to the https URL login stored, and
// find that server's token.
func TestCanonicalServerAddr_SchemelessResolvesToStoredURL(t *testing.T) {
	withTempHome(t)
	seedServerCreds(t, "https://cluster.example.com")

	got := canonicalServerAddr("cluster.example.com")
	if got != "https://cluster.example.com" {
		t.Fatalf("canonicalServerAddr = %q, want the stored https URL", got)
	}
	if tok := resolveAuthToken(got); tok != "tok-https://cluster.example.com" {
		t.Fatalf("token = %q, want the stored token", tok)
	}
}

func TestCanonicalServerAddr_LeavesOtherInputsAlone(t *testing.T) {
	withTempHome(t)
	seedServerCreds(t, "https://cluster.example.com")

	for _, in := range []string{"", "http://cluster.example.com", "other.example.com", "https://cluster.example.com"} {
		if got := canonicalServerAddr(in); got != in {
			t.Errorf("canonicalServerAddr(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestNoTokenError_NamesStoredServers(t *testing.T) {
	withTempHome(t)
	seedServerCreds(t, "https://b.example.com", "https://a.example.com")

	msg := noTokenError("c.example.com").Error()
	for _, want := range []string{"c.example.com", "https://a.example.com", "https://b.example.com"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}

func TestNoTokenError_NoCredentialsFile(t *testing.T) {
	withTempHome(t)
	msg := noTokenError("c.example.com").Error()
	if !strings.Contains(msg, "containarium login") || strings.Contains(msg, "logged in to") {
		t.Errorf("unexpected message %q", msg)
	}
}
