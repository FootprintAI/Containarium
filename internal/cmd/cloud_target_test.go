package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/credentials"
)

func TestIsCloudTarget(t *testing.T) {
	// A `ctnr_` token is a one-way cloud signal, independent of any creds file.
	if !isCloudTarget("https://anything", "ctnr_abc.def") {
		t.Fatal("ctnr_ token must classify as cloud")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = seedCreds(t, home, "", map[string]credentials.ServerCreds{
		"https://cloud.example":  {Token: "eyJcloud", AccessModel: credentials.AccessModelToken},
		"https://daemon.example": {Token: "eyJdaemon", AccessModel: credentials.AccessModelSSHKey},
	})

	// A cloud login whose token isn't prefix-identifiable → cloud via AccessModel.
	if !isCloudTarget("https://cloud.example", "eyJcloud") {
		t.Error("server with AccessModelToken must classify as cloud")
	}
	// Self-hosted AccessModel + a JWT → not cloud.
	if isCloudTarget("https://daemon.example", "eyJdaemon") {
		t.Error("server with AccessModelSSHKey must NOT classify as cloud")
	}
	// Unknown server + a JWT → not cloud.
	if isCloudTarget("https://unknown.example", "eyJrandom") {
		t.Error("unknown server + JWT must NOT classify as cloud")
	}
}

func TestErrUnsupportedOnCloud(t *testing.T) {
	err := errUnsupportedOnCloud("system info", "use `containarium backends`")
	if err == nil || !strings.Contains(err.Error(), "not available on the hosted control plane") {
		t.Fatalf("err = %v, want the host-level marker", err)
	}
	if !strings.Contains(err.Error(), "use `containarium backends`") {
		t.Errorf("err = %q, want the alternative suggestion appended", err)
	}
}
