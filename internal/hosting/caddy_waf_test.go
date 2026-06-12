package hosting

import (
	"strings"
	"testing"
)

func TestXcaddyBuildArgs(t *testing.T) {
	// Without WAF: provider + caddy-l4 only, no coraza.
	noWAF := strings.Join(xcaddyBuildArgs("github.com/caddy-dns/cloudflare", false, "/usr/local/bin/caddy"), " ")
	if strings.Contains(noWAF, "coraza") {
		t.Fatalf("default build must NOT pull coraza: %s", noWAF)
	}
	if !strings.Contains(noWAF, "caddy-l4") || !strings.Contains(noWAF, "cloudflare") {
		t.Fatalf("build missing base modules: %s", noWAF)
	}

	// With WAF: coraza module added.
	waf := strings.Join(xcaddyBuildArgs("github.com/caddy-dns/cloudflare", true, "/usr/local/bin/caddy"), " ")
	if !strings.Contains(waf, corazaCaddyModule) {
		t.Fatalf("WAF build must include the coraza module: %s", waf)
	}
	// Output is last.
	args := xcaddyBuildArgs("m", true, "/out")
	if args[len(args)-2] != "--output" || args[len(args)-1] != "/out" {
		t.Fatalf("--output must be last: %v", args)
	}
}
