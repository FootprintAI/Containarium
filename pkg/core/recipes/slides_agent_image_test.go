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
// that the proxy fronts every path with the forwarded scheme and takes the
// zero-click login only as a single-use token posted to the login helper
// (#3486; the helper's behaviour and the real Caddyfile are tested in
// images/slides-agent/wsauth), and that the entrypoint fails closed and seeds
// the deck tree without clobbering it.

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
		// The login helper (#3486): built from the non-test sources alone,
		// standard library only, on the pinned Go image.
		"COPY images/slides-agent/wsauth/main.go images/slides-agent/wsauth/wsauth.go ./",
		"go mod init slides-wsauth",
		"COPY --from=wsauth /out/slides-wsauth /usr/local/bin/slides-wsauth",
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
		"auto_https off",      // the edge terminates TLS
		"admin off",           // no admin API on the box network
		"basic_auth",          // unauthenticated requests are refused
		"{$SLIDES_AUTH_USER}", // credentials come from the staged env, never the image
		"{$SLIDES_AUTH_HASH}", // bcrypt hash
		// Zero-click login (#3486): exactly the bootstrap path goes to the
		// login helper's proxy-facing listener, which serves the page and
		// redeems the token.
		"handle /__ws_login {\n\t\treverse_proxy 127.0.0.1:9098\n\t}",
		// The session cookie, anchored to the name boundary and of the
		// helper's shape, checked with the helper on every request.
		// __Host-: a sibling subdomain cannot plant it (#3486 follow-up).
		`header_regexp Cookie "(^|;\s*)__Host-ws_session=[A-Za-z0-9_-]{43}($|;)"`,
		// Stripped before the dev server; the app's own cookies pass.
		`header_up Cookie "__Host-ws_session=[^;]*;?\s*" ""`,
		"forward_auth 127.0.0.1:9098 {\n\t\t\turi /__session\n\t\t}",
		"not header Authorization *", // basic-auth credentials always take the basic-auth path
		"127.0.0.1:5173",             // the dev server stays on loopback
		"X-Forwarded-Proto https",    // the request guard compares Origin against the forwarded scheme
	} {
		if !strings.Contains(cf, want) {
			t.Errorf("Caddyfile missing %q", want)
		}
	}
	for _, banned := range []string{
		"SLIDES_WS_TOKEN", // no static zero-click token
		"ws_auth",         // nor its cookie
		"query t",         // no token in a query string
		"9099",            // the daemon-facing mint listener is never proxied
		"Set-Cookie",      // the proxy sets no cookie itself; the helper does
	} {
		if strings.Contains(cf, banned) {
			t.Errorf("Caddyfile must not contain %q (#3486)", banned)
		}
	}
	// No access log: a `log` directive would write request lines.
	if regexp.MustCompile(`(?m)^\s*log\b`).MatchString(cf) {
		t.Error("Caddyfile must not enable an access log")
	}
	// Every request proxied to the dev server forwards the https scheme, and
	// the only other upstream is the helper.
	toDev := strings.Count(cf, "reverse_proxy 127.0.0.1:5173")
	if strings.Count(cf, `header_up Cookie "__Host-ws_session=`) != toDev {
		t.Error("every dev-server reverse_proxy block must strip the session cookie")
	}
	if regexp.MustCompile(`[^-]ws_session`).MatchString(cf) {
		t.Error("the session cookie must carry the __Host- prefix everywhere")
	}
	if toDev != 2 || toDev != strings.Count(cf, "header_up X-Forwarded-Proto https") {
		t.Errorf("want the two dev-server reverse_proxy blocks, each with X-Forwarded-Proto https; got %d", toDev)
	}
	if strings.Count(cf, "reverse_proxy") != toDev+1 || strings.Count(cf, "reverse_proxy 127.0.0.1:9098") != 1 {
		t.Error("the only upstreams are the dev server and, for /__ws_login, the helper")
	}
	// Exactly three routes: the bootstrap, the cookie path, and the
	// basic-auth fallback. The cookie path checks the session before it
	// proxies; the fallback carries basic_auth: no path reaches the dev
	// server unauthenticated.
	handles := regexp.MustCompile(`(?m)^\s*handle(\s+\S+)?\s*\{`).FindAllStringSubmatch(cf, -1)
	var got []string
	for _, h := range handles {
		got = append(got, strings.TrimSpace(h[1]))
	}
	if strings.Join(got, ",") != "/__ws_login,@session," {
		t.Errorf("handles = %q, want /__ws_login, @session and one unmatched fallback", got)
	}
	session := cf[strings.Index(cf, "handle @session {"):]
	session = session[:strings.Index(session, "\n\t}\n")]
	if fa, rp := strings.Index(session, "forward_auth"), strings.Index(session, "reverse_proxy 127.0.0.1:5173"); fa < 0 || rp < fa {
		t.Errorf("the cookie path must check the session before it proxies:\n%s", session)
	}
	fallback := cf[strings.LastIndex(cf, "handle {"):]
	if ba, rp := strings.Index(fallback, "basic_auth"), strings.Index(fallback, "reverse_proxy"); ba < 0 || rp < ba {
		t.Error("the fallback must authenticate with basic_auth before it proxies")
	}
}

// The helper listens where the daemon's probe and the Caddyfile expect it.
func TestSlidesAgentLoginHelperContract(t *testing.T) {
	src := readImageFile(t, "wsauth/wsauth.go")
	for _, want := range []string{
		`mintAddr  = "127.0.0.1:9099"`, // GetWorkspaceAccess's in-box probe
		`proxyAddr = "127.0.0.1:9098"`, // the Caddyfile's helper upstream
		`"GET /__mint"`,
		`"POST /__ws_login"`,
		`"/__session"`,
		"tokenTTL = 120 * time.Second",
		"cookieSameSite = http.SameSiteNoneMode",
		`sessionCookie = "__Host-ws_session"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("wsauth.go missing %q", want)
		}
	}
	// Standard library only: the image build has no module download.
	imports := regexp.MustCompile(`(?s)import \((.*?)\)`).FindStringSubmatch(src)
	if imports == nil || regexp.MustCompile(`"[^"/]+\.[^"/]+/`).MatchString(imports[1]) {
		t.Error("wsauth.go must import only the standard library")
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
	// The login helper runs beside the proxy, and its exit stops the
	// container like the other two (#3486).
	if !strings.Contains(ep, "slides-wsauth &") || !strings.Contains(ep, `wait -n "$DEV_PID" "$AUTH_PID" "$CADDY_PID"`) {
		t.Error("entrypoint must run slides-wsauth and stop when it exits")
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
	for _, tc := range []struct{ name, user, hash string }{
		{"no hash", "deck", ""},
		{"no user", "", "$2a$14$x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", filepath.Join(slidesAgentImageDir, "entrypoint.sh")) //nolint:gosec // fixed path
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(),
				"SLIDES_WORKSPACE=" + t.TempDir(), "SLIDES_TEMPLATE=" + t.TempDir(),
				"SLIDES_AUTH_USER=" + tc.user, "SLIDES_AUTH_HASH=" + tc.hash}
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
			"SLIDES_AUTH_USER=deck", "SLIDES_AUTH_HASH=$2a$14$x"}
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
