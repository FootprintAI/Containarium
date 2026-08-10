// Package agentbox holds tests for the agent-box image's shell helpers.
//
// The helpers are shell, not Go, but they are as load-bearing as any code
// here: secrets-env.sh is what turns a mounted secret into the session
// environment (#1190), and a mistake in it is either a secret that never
// arrives or an environment a tenant can corrupt. Running it under `sh` in a
// test is the only way to check either without building the image.
package agentbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runWithSecrets writes the given files into a fake secrets mount, sources
// the snippet against it, and returns the resulting environment.
func runWithSecrets(t *testing.T, files map[string]string) map[string]string {
	t.Helper()

	dir := t.TempDir()
	mount := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(mount, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(mount, name), []byte(content), 0o400); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	script, err := os.ReadFile("secrets-env.sh")
	if err != nil {
		t.Fatalf("read snippet: %v", err)
	}
	// Point the snippet at the fake mount. The path is a literal in the
	// snippet because the real one is fixed by the pod spec.
	body := strings.ReplaceAll(string(script), "/run/secrets", mount)

	// env -0 (NUL-separated), not plain env: splitting on newlines cannot
	// distinguish "value" from "value\n", so a test for the trailing-newline
	// strip would pass either way.
	out, err := exec.Command("sh", "-c", body+"\nenv -0").Output()
	if err != nil {
		t.Fatalf("run snippet: %v", err)
	}

	env := map[string]string{}
	for _, entry := range strings.Split(string(out), "\x00") {
		if k, v, ok := strings.Cut(entry, "="); ok {
			env[k] = v
		}
	}
	return env
}

func TestSecretsEnv_ExportsEachSecret(t *testing.T) {
	env := runWithSecrets(t, map[string]string{
		"API_TOKEN": "s3cret",
		"DB_URL":    "postgres://host/db",
	})

	if env["API_TOKEN"] != "s3cret" {
		t.Errorf("API_TOKEN = %q, want the secret — an env-delivery secret that never reaches "+
			"the environment is the whole of #1190", env["API_TOKEN"])
	}
	if env["DB_URL"] != "postgres://host/db" {
		t.Errorf("DB_URL = %q", env["DB_URL"])
	}
}

// A file written by the kubelet ends with whatever the value contained. A
// consumer reading an env var does not expect a trailing newline.
func TestSecretsEnv_StripsTheTrailingNewline(t *testing.T) {
	env := runWithSecrets(t, map[string]string{"TOKEN": "value\n"})
	if env["TOKEN"] != "value" {
		t.Errorf("TOKEN = %q, want %q — a trailing newline breaks a token used in a header",
			env["TOKEN"], "value")
	}
}

// The compose dotenv is consumed as a file by `env_file:`. Exporting it would
// create one variable holding the whole file. It is refused by the identifier
// check rather than by a name-specific case, so this pins the behaviour, not
// the mechanism.
func TestSecretsEnv_SkipsTheComposeDotenv(t *testing.T) {
	env := runWithSecrets(t, map[string]string{
		"secrets.env": "A=1\nB=2\n",
		"REAL":        "v",
	})

	if _, exported := env["secrets.env"]; exported {
		t.Error("the compose dotenv was exported as a variable")
	}
	if env["REAL"] != "v" {
		t.Error("skipping the dotenv also skipped a real secret")
	}
}

// A tenant must not be able to redirect what the session executes by naming
// a secret PATH.
func TestSecretsEnv_RefusesToOverrideExecutionVariables(t *testing.T) {
	env := runWithSecrets(t, map[string]string{
		"PATH":       "/tmp/evil",
		"LD_PRELOAD": "/tmp/evil.so",
		"SAFE":       "ok",
	})

	if env["PATH"] == "/tmp/evil" {
		t.Error("a secret named PATH replaced the session's PATH — a tenant secret would decide " +
			"which binaries the session runs")
	}
	if env["LD_PRELOAD"] == "/tmp/evil.so" {
		t.Error("a secret named LD_PRELOAD was exported — it would be injected into every " +
			"process the session starts")
	}
	if env["SAFE"] != "ok" {
		t.Error("refusing a dangerous name also dropped a legitimate secret")
	}
}

// A name that is not a shell identifier must be skipped without stopping the
// rest — one bad name should not cost a tenant every other secret.
func TestSecretsEnv_SkipsInvalidNamesWithoutDroppingTheRest(t *testing.T) {
	env := runWithSecrets(t, map[string]string{
		"not-an-identifier": "x",
		"1LEADING_DIGIT":    "y",
		"GOOD":              "z",
	})

	if env["GOOD"] != "z" {
		t.Error("an unusable secret name stopped the valid ones loading — a single bad name " +
			"would cost the tenant every other secret")
	}
	if _, ok := env["not-an-identifier"]; ok {
		t.Error("exported a name that is not a shell identifier")
	}
}

// Kubernetes projects each key as a symlink into a ..data directory. If the
// snippet did not follow symlinks, every secret would be skipped in the one
// arrangement that matters — the real one.
func TestSecretsEnv_FollowsTheKubeletsSymlinkLayout(t *testing.T) {
	dir := t.TempDir()
	mount := filepath.Join(dir, "secrets")
	data := filepath.Join(mount, "..data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(data, "TOKEN"), []byte("v"), 0o400); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(filepath.Join(data, "TOKEN"), filepath.Join(mount, "TOKEN")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	script, err := os.ReadFile("secrets-env.sh")
	if err != nil {
		t.Fatalf("read snippet: %v", err)
	}
	body := strings.ReplaceAll(string(script), "/run/secrets", mount)
	out, err := exec.Command("sh", "-c", body+"\nenv").Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !strings.Contains(string(out), "TOKEN=v") {
		t.Errorf("a secret projected the way the kubelet actually projects it was not exported:\n%s", out)
	}
	// The ..data directory itself must not become a variable.
	if strings.Contains(string(out), "..data=") {
		t.Error("the kubelet's ..data directory was exported as a variable")
	}
}

// An empty mount, or none at all, must not fail the session — a box whose
// tenant has set no secrets is the common case.
func TestSecretsEnv_EmptyMountIsFine(t *testing.T) {
	env := runWithSecrets(t, nil)
	if len(env) == 0 {
		t.Fatal("the snippet produced no environment at all")
	}
	for k := range env {
		if strings.HasPrefix(k, "/") || strings.Contains(k, "*") {
			t.Errorf("an unmatched glob leaked into the environment as %q", k)
		}
	}
}

// --- image wiring -----------------------------------------------------

func readImageFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// The snippet only does anything if the image installs it and both session
// modes reach it. Dropping any one of these is silent: the box comes up, SSH
// works, and secrets are simply absent from the environment.
func TestImageInstallsTheSecretsSnippet(t *testing.T) {
	dockerfile := readImageFile(t, "Dockerfile")

	for _, want := range []string{
		"secrets-env.sh /usr/local/lib/containarium/secrets-env.sh",
		"session.sh /usr/local/bin/agent-box-session",
		"/etc/profile.d/10-containarium-secrets.sh",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("the image no longer installs %q — secrets would be mounted and never "+
				"loaded into the session environment (#1190)", want)
		}
	}
}

// The forced-command mode is the default, so this is the path almost every
// session takes. Running agent-box directly would skip the secrets entirely.
func TestEntrypointRunsTheSessionWrapper(t *testing.T) {
	entrypoint := readImageFile(t, "entrypoint.sh")

	if !strings.Contains(entrypoint, "-c /usr/local/bin/agent-box-session") {
		t.Error("the forced command no longer goes through the session wrapper — the default " +
			"session mode would start with no tenant secrets in its environment (#1190)")
	}
}

// The wrapper must load secrets and then become agent-box. If it forgot the
// exec, the MCP server would not be the session's process.
func TestSessionWrapperLoadsSecretsThenExecs(t *testing.T) {
	wrapper := readImageFile(t, "session.sh")

	loads := strings.Index(wrapper, "secrets-env.sh")
	execs := strings.Index(wrapper, "exec /usr/local/bin/agent-box")
	if loads < 0 {
		t.Fatal("the session wrapper does not load the secrets snippet")
	}
	if execs < 0 {
		t.Fatal("the session wrapper does not exec agent-box")
	}
	if loads > execs {
		t.Error("the wrapper execs agent-box before loading secrets — anything after an exec " +
			"never runs, so the secrets would never be loaded")
	}
}
