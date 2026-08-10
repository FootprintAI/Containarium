package k8s

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These guard the two pins in scripts/k8s-e2e.sh that decide what the kind
// e2e is actually evidence *about*. Both have already failed in ways that
// cost a CI cluster build to discover, and both are checkable offline.
//
// They read the script as text on purpose: the point is to catch a bad pin
// before CI spends ~90s building a cluster to find out, so the check has to
// be cheaper than running the thing it guards.

const (
	repoRoot     = "../../../.."
	e2eScript    = repoRoot + "/scripts/k8s-e2e.sh"
	goModPath    = repoRoot + "/go.mod"
	agentSandbox = "sigs.k8s.io/agent-sandbox"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// scriptSandboxVersion extracts the AGENT_SANDBOX_VERSION default.
func scriptSandboxVersion(t *testing.T, script string) string {
	t.Helper()
	m := regexp.MustCompile(`AGENT_SANDBOX_VERSION="\$\{AGENT_SANDBOX_VERSION:-(v[0-9][^}]*)\}"`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("could not find the AGENT_SANDBOX_VERSION default in scripts/k8s-e2e.sh")
	}
	return m[1]
}

// The e2e is only evidence about the controller we build against. Pinned to
// an older release it silently exercises older behaviour — which is exactly
// what happened: the script sat at v0.5.1 while go.mod moved to v0.5.4, the
// release that makes the Suspended condition always present (#1196). The
// e2e covered only the pre-0.5.4 fallback path and nobody could tell.
func TestE2EControllerVersionMatchesGoMod(t *testing.T) {
	gomod := readFile(t, goModPath)

	m := regexp.MustCompile(regexp.QuoteMeta(agentSandbox) + `\s+(v[0-9]\S*)`).FindStringSubmatch(gomod)
	if m == nil {
		t.Fatalf("could not find %s in go.mod", agentSandbox)
	}
	want := m[1]

	if got := scriptSandboxVersion(t, readFile(t, e2eScript)); got != want {
		t.Errorf("scripts/k8s-e2e.sh installs agent-sandbox %s but go.mod builds against %s.\n"+
			"The e2e would be exercising a different controller than the one we ship against, "+
			"so a green run would not mean what it appears to mean. Bump the script (and check "+
			"the release asset name — see TestE2EControllerAssetNameMatchesVersion).", got, want)
	}
}

// parseSemver turns "v0.5.4" into comparable parts. Pre-release/build
// suffixes are ignored: the asset rename tracks the release line, not the
// suffix.
func parseSemver(t *testing.T, v string) (major, minor, patch int) {
	t.Helper()
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("unparseable version %q", v)
	}
	out := make([]int, 3)
	for i, p := range parts {
		// Drop any -rc1/+meta suffix on the patch component.
		if idx := strings.IndexAny(p, "-+"); idx >= 0 {
			p = p[:idx]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("unparseable version %q: component %q: %v", v, parts[i], err)
		}
		out[i] = n
	}
	return out[0], out[1], out[2]
}

// lessThan reports whether major.minor.patch precedes oMajor.oMinor.oPatch.
func lessThan(major, minor, patch, oMajor, oMinor, oPatch int) bool {
	if major != oMajor {
		return major < oMajor
	}
	if minor != oMinor {
		return minor < oMinor
	}
	return patch < oPatch
}

// Upstream renamed the install asset manifest.yaml -> sandbox.yaml in
// v0.5.2. v0.5.1 was the last release carrying the old name, so bumping the
// version without changing the URL 404s at install time — which is exactly
// how the first attempt at the bump broke, after CI had already spent the
// time to build a cluster.
//
// Both names are release *assets*, so nothing in the repo or the compiler
// can catch a bad pairing. This test encodes the one upstream fact that
// makes it decidable offline.
func TestE2EControllerAssetNameMatchesVersion(t *testing.T) {
	script := readFile(t, e2eScript)
	version := scriptSandboxVersion(t, script)
	major, minor, patch := parseSemver(t, version)

	// The rename landed in v0.5.2.
	oldNaming := lessThan(major, minor, patch, 0, 5, 2)

	wantAsset := "sandbox.yaml"
	if oldNaming {
		wantAsset = "manifest.yaml"
	}

	m := regexp.MustCompile(`releases/download/\$\{AGENT_SANDBOX_VERSION\}/(\S+?)"`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("could not find the agent-sandbox release asset URL in scripts/k8s-e2e.sh")
	}
	gotAsset := m[1]

	// sandbox-with-extensions.yaml is a legitimate post-rename choice; it
	// just installs more than we need. Accept it rather than forcing a
	// future reviewer to fight this test over a deliberate decision.
	if !oldNaming && gotAsset == "sandbox-with-extensions.yaml" {
		return
	}

	if gotAsset != wantAsset {
		t.Errorf("scripts/k8s-e2e.sh installs asset %q for agent-sandbox %s, want %q.\n"+
			"Upstream renamed manifest.yaml -> sandbox.yaml in v0.5.2; a mismatched pair "+
			"404s at install time and fails the kind e2e for a reason that has nothing to "+
			"do with the change under test.", gotAsset, version, wantAsset)
	}
}
