package recipes

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The prebaked slides-agent image definition (#3434) lives in
// images/slides-agent/. These tests pin what the recipe relies on at the
// definition level: the framework commit, what is installed at build time,
// that the proxy fronts every path with the forwarded scheme, and that the
// entrypoint fails closed and seeds the deck tree without clobbering it.

const slidesAgentImageDir = "../../../images/slides-agent"

// openSlideCommit is the pinned open-slide commit (MIT); the Dockerfile must
// fetch exactly this and verify it.
const openSlideCommit = "1ce6bd5268efeaf4cc3bed28112ac770fc5f3b34"

func readImageFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(slidesAgentImageDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestSlidesAgentDockerfile(t *testing.T) {
	df := readImageFile(t, "Dockerfile")
	for _, want := range []string{
		"OPEN_SLIDE_COMMIT=" + openSlideCommit,
		`git rev-parse HEAD`,                 // the checkout is verified against the pin, not trusted
		"--frozen-lockfile",                  // the framework's own lockfile decides its dependency set
		"chromium",                           // headless Chromium for PDF export
		"/usr/bin/caddy",                     // the auth proxy ships in the image: no pull at box start
		"scripts/install-xcaddy.sh",          // Caddy is built with the repo's checksum-pinned xcaddy
		"xcaddy build \"${CADDY_VERSION}\"",  // from a pinned release, on the pinned Go image
		"rm -rf /usr/local/lib/node_modules", // no package manager in the runtime stage
		".pnpm/undici@*",
		"shadcn/tailwind.css", // the scaffolding CLI's never-imported server tree is pruned
		"images/slides-agent/Caddyfile",
		"images/slides-agent/entrypoint.sh",
		"images/slides-agent/open-slide.config.ts",
		"images/slides-agent/slides-print-pdf",
		"node --check /usr/local/bin/slides-print-pdf", // the printer is syntax-checked at build
		"USER ",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile missing %q", want)
		}
	}
	// Every base image is pinned to an exact version; nothing floats.
	from := regexp.MustCompile(`(?m)^FROM\s+(\S+)`)
	pinned := regexp.MustCompile(`:\d+\.\d+\.\d+`)
	for _, m := range from.FindAllStringSubmatch(df, -1) {
		ref := m[1]
		if strings.HasPrefix(ref, "${") { // an ARG: find its default
			name := strings.TrimSuffix(strings.TrimPrefix(ref, "${"), "}")
			def := regexp.MustCompile(`(?m)^ARG\s+` + regexp.QuoteMeta(name) + `=(\S+)`).FindStringSubmatch(df)
			if def == nil {
				t.Errorf("FROM %s has no ARG default", ref)
				continue
			}
			ref = def[1]
		}
		if !pinned.MatchString(ref) {
			t.Errorf("base image %q is not pinned to an exact version", ref)
		}
	}
	// Upstream content is data: nothing fetched from it is piped into a shell.
	if regexp.MustCompile(`curl[^\n]*\|\s*(ba)?sh`).MatchString(df) {
		t.Error("Dockerfile pipes a download into a shell")
	}
	// The build never runs the dependencies' own lifecycle scripts.
	if !strings.Contains(df, "--ignore-scripts") {
		t.Error("Dockerfile must install the workspace with --ignore-scripts")
	}
}

func TestSlidesAgentCaddyfile(t *testing.T) {
	cf := readImageFile(t, "Caddyfile")
	for _, want := range []string{
		"auto_https off",          // the edge terminates TLS
		"admin off",               // no admin API on the box network
		"basic_auth",              // unauthenticated requests are refused
		"{$SLIDES_AUTH_USER}",     // credentials come from the staged env, never the image
		"{$SLIDES_AUTH_HASH}",     // bcrypt hash
		"{$SLIDES_WS_TOKEN}",      // per-box session token
		"/__ws_login",             // zero-click bootstrap route
		"SameSite=None",           // cookie sent from the embedding console's iframe
		`(^|;\s*)ws_auth=`,        // anchored cookie match
		"127.0.0.1:5173",          // the dev server stays on loopback
		"X-Forwarded-Proto https", // the request guard compares Origin against the forwarded scheme
	} {
		if !strings.Contains(cf, want) {
			t.Errorf("Caddyfile missing %q", want)
		}
	}
	// Every proxied path forwards the https scheme: one header_up per
	// reverse_proxy block, and no upstream other than the loopback dev server.
	proxies := strings.Count(cf, "reverse_proxy")
	if proxies == 0 || proxies != strings.Count(cf, "header_up X-Forwarded-Proto https") {
		t.Errorf("want one X-Forwarded-Proto https per reverse_proxy block; got %d blocks", proxies)
	}
	if proxies != strings.Count(cf, "reverse_proxy 127.0.0.1:5173") {
		t.Error("every reverse_proxy must target 127.0.0.1:5173")
	}
	// The only handle without the cookie gate is the one carrying basic_auth:
	// no path reaches the dev server unauthenticated.
	handles := regexp.MustCompile(`(?m)^\s*handle(\s+@\w+)?\s*\{`).FindAllStringSubmatch(cf, -1)
	var open int
	for _, h := range handles {
		if strings.TrimSpace(h[1]) == "" {
			open++
		}
	}
	if open != 1 {
		t.Errorf("want exactly one unmatched handle (the basic_auth fallback); got %d", open)
	}
}

func TestSlidesAgentOpenSlideConfig(t *testing.T) {
	cfg := readImageFile(t, "open-slide.config.ts")
	for _, want := range []string{
		"allowedHosts",         // the proxy's Host reaches the dev server
		"SLIDES_ALLOWED_HOSTS", // a deploy may narrow it
		"enabled: false",       // agent panel off: its loopback gate is void behind the proxy
		"port: 5173",
		"/workspace/slides", // the deck tree on the box disk
		"/workspace/themes",
		"/workspace/assets",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("open-slide.config.ts missing %q", want)
		}
	}
}

// The dev server listens on the loopback address the proxy dials, never on the
// box's address: the proxy is the only way in.
func TestSlidesAgentEntrypointBindsLoopback(t *testing.T) {
	ep := readImageFile(t, "entrypoint.sh")
	if !strings.Contains(ep, "bin.js dev --host 127.0.0.1 --port 5173") {
		t.Error("entrypoint must start the dev server with --host 127.0.0.1 --port 5173")
	}
	if strings.Contains(ep, "--host 0.0.0.0") || strings.Contains(ep, "--host true") {
		t.Error("entrypoint must not expose the dev server beyond loopback")
	}
}

// slides-print-pdf (#3434, maintainer decision 2): prints a built site to a
// PDF with the framework's own export driven over the DevTools protocol. These
// are the invariants the recipe documents; the offline smoke test on the PR
// proves the output.
func TestSlidesAgentPrintPDFScript(t *testing.T) {
	src := readImageFile(t, "slides-print-pdf")
	if !strings.HasPrefix(src, "#!/usr/bin/env node\n") {
		t.Error("slides-print-pdf must be a node script")
	}
	for _, want := range []string{
		"usage: slides-print-pdf <site dir | http(s) url> <out.pdf> [deck-id]",
		"server.listen(0, '127.0.0.1'", // the built site is served on loopback only
		"--headless=new",               // headless Chromium
		"--remote-debugging-port=0",    // DevTools on an ephemeral loopback port
		"new WebSocket(",               // Node's built-in client: no dependency
		"window.print = () =>",         // the export never blocks in a print dialog
		"'Page.printToPDF'",            // the capture
		"preferCSSPageSize: true",      // the framework's @page 1920x1080 wins
		"printBackground: true",
		"#os-print-root .os-print-frame", // page count from the export's print root
		"afterprint",                     // the export's own cleanup is allowed to run
		"export as pdf",                  // the toolbar item, matched case-insensitively
	} {
		if !strings.Contains(src, want) {
			t.Errorf("slides-print-pdf missing %q", want)
		}
	}
	if strings.Contains(src, "require('ws')") || strings.Contains(src, "puppeteer") || strings.Contains(src, "playwright") {
		t.Error("slides-print-pdf must not depend on a package outside Node")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available for a syntax check")
	}
	out, err := exec.Command("node", "--check", filepath.Join(slidesAgentImageDir, "slides-print-pdf")).CombinedOutput() //nolint:gosec // fixed path
	if err != nil {
		t.Errorf("node --check: %v\n%s", err, out)
	}
	// Usage errors exit 2 before anything is served or launched.
	cmd := exec.Command("node", filepath.Join(slidesAgentImageDir, "slides-print-pdf")) //nolint:gosec // fixed path
	cmd.Env = []string{"PATH=/usr/bin:/bin:" + filepath.Dir(mustLookPath(t, "node"))}
	out, err = cmd.CombinedOutput()
	if code := exitCode(err); code != 2 || !strings.Contains(string(out), "usage:") {
		t.Errorf("no arguments: exit %d, want 2 with usage\n%s", code, out)
	}
	cmd = exec.Command("node", filepath.Join(slidesAgentImageDir, "slides-print-pdf"), t.TempDir(), "out.txt") //nolint:gosec // fixed path
	cmd.Env = []string{"PATH=/usr/bin:/bin:" + filepath.Dir(mustLookPath(t, "node"))}
	out, err = cmd.CombinedOutput()
	if code := exitCode(err); code != 2 || !strings.Contains(string(out), ".pdf") {
		t.Errorf("non-pdf output: exit %d, want 2 naming .pdf\n%s", code, out)
	}
	cmd = exec.Command("node", filepath.Join(slidesAgentImageDir, "slides-print-pdf"), t.TempDir(), "out.pdf") //nolint:gosec // fixed path
	cmd.Env = []string{"PATH=/usr/bin:/bin:" + filepath.Dir(mustLookPath(t, "node"))}
	out, err = cmd.CombinedOutput()
	if code := exitCode(err); code != 2 || !strings.Contains(string(out), "index.html") {
		t.Errorf("unbuilt site: exit %d, want 2 naming index.html\n%s", code, out)
	}
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func TestSlidesAgentScriptsShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not available")
	}
	for _, name := range []string{"entrypoint.sh", "slides-render", "open-slide"} {
		out, err := exec.Command("shellcheck", filepath.Join(slidesAgentImageDir, name)).CombinedOutput() //nolint:gosec // fixed path
		if err != nil {
			t.Errorf("shellcheck %s: %v\n%s", name, err, out)
		}
	}
}

// The entrypoint refuses to start without auth material, before it touches
// the dev server or the proxy. PATH carries no node or caddy, so reaching
// either would fail differently from the refusal asserted here.
func TestSlidesAgentEntrypointFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, user, hash, token string }{
		{"no hash", "deck", "", "0123456789abcdef0123456789abcdef"},
		{"no token", "deck", "$2a$14$x", ""},
		{"no user", "", "$2a$14$x", "0123456789abcdef0123456789abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", filepath.Join(slidesAgentImageDir, "entrypoint.sh")) //nolint:gosec // fixed path
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(),
				"SLIDES_WORKSPACE=" + t.TempDir(), "SLIDES_TEMPLATE=" + t.TempDir(),
				"SLIDES_AUTH_USER=" + tc.user, "SLIDES_AUTH_HASH=" + tc.hash, "SLIDES_WS_TOKEN=" + tc.token}
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("entrypoint started without auth material:\n%s", out)
			}
			if !strings.Contains(string(out), "auth") {
				t.Errorf("refusal should name the missing auth material:\n%s", out)
			}
		})
	}
}

// Seeding: a fresh workspace gets the template's deck tree and agent files; an
// existing one is left alone so an idle-stop and restart resumes the deck.
func TestSlidesAgentEntrypointSeedsWorkspace(t *testing.T) {
	tpl := t.TempDir()
	for _, f := range []string{"slides/getting-started/index.tsx", "slides/.folders.json", "themes/.gitkeep", "assets/.gitkeep", "AGENTS.md", ".agents/skills/create-slide/SKILL.md"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(tpl, f)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tpl, f), []byte("template "+f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("AGENTS.md", filepath.Join(tpl, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tpl, ".claude/skills"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../.agents/skills/create-slide", filepath.Join(tpl, ".claude/skills/create-slide")); err != nil {
		t.Fatal(err)
	}

	app := t.TempDir()
	run := func(ws string) string {
		cmd := exec.Command("bash", filepath.Join(slidesAgentImageDir, "entrypoint.sh")) //nolint:gosec // fixed path
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "SLIDES_SEED_ONLY=1",
			"SLIDES_WORKSPACE=" + ws, "SLIDES_TEMPLATE=" + tpl, "SLIDES_APP=" + app,
			"SLIDES_AUTH_USER=deck", "SLIDES_AUTH_HASH=$2a$14$x", "SLIDES_WS_TOKEN=0123456789abcdef0123456789abcdef"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("entrypoint seed: %v\n%s", err, out)
		}
		return string(out)
	}

	// Fresh workspace: everything is seeded, symlinks included.
	ws := t.TempDir()
	run(ws)
	for _, f := range []string{"slides/getting-started/index.tsx", "slides/.folders.json", "themes/.gitkeep", "assets/.gitkeep", "AGENTS.md", ".agents/skills/create-slide/SKILL.md"} {
		b, err := os.ReadFile(filepath.Join(ws, f))
		if err != nil || string(b) != "template "+f {
			t.Errorf("%s not seeded: %v %q", f, err, b)
		}
	}
	if b, err := os.ReadFile(filepath.Join(ws, ".claude/skills/create-slide/SKILL.md")); err != nil || !strings.HasSuffix(string(b), "create-slide/SKILL.md") {
		t.Errorf(".claude/skills link not usable: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(ws, "CLAUDE.md")); err != nil || string(b) != "template AGENTS.md" {
		t.Errorf("CLAUDE.md link not usable: %v", err)
	}
	// Slides resolve @open-slide/core and react through the image's node_modules.
	if target, err := os.Readlink(filepath.Join(ws, "node_modules")); err != nil || target != filepath.Join(app, "node_modules") {
		t.Errorf("node_modules link = %q, %v; want %s", target, err, filepath.Join(app, "node_modules"))
	}

	// Resumed workspace: the user's deck and edits survive; a missing piece is
	// still filled in.
	if err := os.WriteFile(filepath.Join(ws, "slides/getting-started/index.tsx"), []byte("edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "slides/my-deck"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(ws, "themes")); err != nil {
		t.Fatal(err)
	}
	run(ws)
	if b, _ := os.ReadFile(filepath.Join(ws, "slides/getting-started/index.tsx")); string(b) != "edited" {
		t.Errorf("seeding overwrote a user edit: %q", b)
	}
	if _, err := os.Stat(filepath.Join(ws, "slides/my-deck")); err != nil {
		t.Errorf("seeding removed a user deck: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ws, "themes/.gitkeep")); err != nil {
		t.Errorf("missing themes dir not re-seeded: %v", err)
	}
}
