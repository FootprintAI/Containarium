package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCaddyModulesInSyncWithMakefile guards the one place #1617's pre-built
// Caddy release asset can silently drift from dnsProviderModules: the
// Makefile's build-caddy target hardcodes its own `--with` list (make has
// no clean way to call back into this package), so nothing else catches a
// provider added to one but not the other — the release binary would ship
// missing a module, and the gap would only surface as a live "unknown
// module" failure the way #1617 itself was filed after (Containarium-cloud
// #1351).
func TestCaddyModulesInSyncWithMakefile(t *testing.T) {
	root, err := repoRootForCaddyMakefileTest()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefile := string(data)

	if idx := strings.Index(makefile, "\nCADDY_VERSION="); idx >= 0 {
		line := makefile[idx+1:]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		makefileVersion := strings.TrimPrefix(line, "CADDY_VERSION=")
		if makefileVersion != CaddyVersion {
			t.Errorf("Makefile's CADDY_VERSION=%s does not match app.CaddyVersion=%s", makefileVersion, CaddyVersion)
		}
	} else {
		t.Error("Makefile has no CADDY_VERSION= line — did the pin get renamed or removed?")
	}

	target := extractMakeTarget(makefile, "build-caddy:")
	if target == "" {
		t.Fatal("Makefile has no build-caddy: target — did it get renamed or removed?")
	}

	for _, mod := range AllDNSProviderModules() {
		if !strings.Contains(target, mod) {
			t.Errorf("Makefile's build-caddy target is missing --with %s (present in dnsProviderModules but not baked into the release binary)", mod)
		}
	}

	// Catch drift in the other direction too: a module the Makefile still
	// lists but that was removed from dnsProviderModules would silently keep
	// shipping in every release forever.
	for _, mod := range extractWithModules(target) {
		if mod == "github.com/mholt/caddy-l4" {
			continue // not a DNS provider module; always present by design
		}
		found := false
		for _, want := range AllDNSProviderModules() {
			if mod == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Makefile's build-caddy target has --with %s, which is no longer in dnsProviderModules — remove it or re-add the provider", mod)
		}
	}
}

// extractMakeTarget returns the recipe lines of a Makefile target (the
// lines between its "name:" header and the next non-indented, non-comment
// line), or "" if not found. Deliberately simple text scanning — this test
// only needs to know what --with flags one target contains, not a full
// Makefile parse.
func extractMakeTarget(makefile, header string) string {
	idx := strings.Index(makefile, "\n"+header)
	if idx == -1 {
		return ""
	}
	// Skip the "\n" + the header line itself, to the recipe body.
	rest := makefile[idx+1+len(header):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:]
	}
	lines := strings.Split(rest, "\n")
	var out strings.Builder
	for _, line := range lines {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			break // next target/section started
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.String()
}

// extractWithModules pulls every "--with <module-path>" argument out of a
// shell snippet, in the order they appear, tolerating the line-continuation
// backslashes Makefile recipes use.
func extractWithModules(recipe string) []string {
	flat := strings.ReplaceAll(recipe, "\\\n", " ")
	fields := strings.Fields(flat)
	var out []string
	for i, f := range fields {
		if f == "--with" && i+1 < len(fields) {
			out = append(out, fields[i+1])
		}
	}
	return out
}

// repoRootForCaddyMakefileTest walks up from the working directory to find
// the repo root (the directory containing go.mod) — this test package's
// working directory is internal/app when `go test` runs it.
func repoRootForCaddyMakefileTest() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
