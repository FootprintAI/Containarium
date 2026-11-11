package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The release path must verify the shipped linux binary is static, not only
// the developer target (#3582).
func TestMakefile_ReleaseAgentBoxBuildRunsTheStaticGate(t *testing.T) {
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	mk := string(b)
	recipe := func(target string) string {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(target) + `:[^\n]*\n((?:\t[^\n]*\n|\n)*)`)
		m := re.FindStringSubmatch(mk)
		if m == nil {
			t.Fatalf("target %s not found", target)
		}
		return m[1]
	}
	all := recipe("build-agent-box-all")
	gated := false
	for _, line := range strings.Split(all, "\n") {
		if strings.Contains(line, "scripts/test-agent-box-static.sh") && strings.Contains(line, "-linux-amd64") {
			gated = true
		}
	}
	if !gated {
		t.Errorf("build-agent-box-all (used by build-release) does not run the static gate on the linux binary:\n%s", all)
	}
}
