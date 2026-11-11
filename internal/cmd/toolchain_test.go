//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/toolchain"
)

func TestPrintToolchainList(t *testing.T) {
	inv := toolchain.Inventory{Release: "v1", Arch: "amd64", ExtraLockSHA256: "abc123", Tools: []toolchain.Tool{
		{Name: "go", Version: "1.27.3", Source: toolchain.SourceManaged},
		{Name: "cobol", Version: "3.2.0", Source: toolchain.SourceExtra},
	}}
	var out bytes.Buffer
	printToolchainList(&out, inv)
	for _, want := range []string{"go", "1.27.3", "managed", "cobol", "3.2.0", "extra", "abc123", "v1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	inv.ExtraLockSHA256 = ""
	out.Reset()
	printToolchainList(&out, inv)
	if strings.Contains(out.String(), "extra lock") {
		t.Errorf("no extra lock line expected:\n%s", out.String())
	}
}
