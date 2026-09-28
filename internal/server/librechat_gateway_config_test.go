package server

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/recipes"
)

// librechatGoldenUpdate mirrors pkg/core/cluster/bootstrap_test.go's -update
// flag/golden convention for this package: `go test ./internal/server/
// -run TestLibreChatPostStart -update` regenerates the fixtures below.
var librechatGoldenUpdate = flag.Bool("librechat-golden-update", false, "rewrite librechat post_start golden files")

// librechatGolden compares got against testdata/<name>, writing it first when
// -librechat-golden-update is set.
func librechatGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *librechatGoldenUpdate {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -librechat-golden-update to create): %v", path, err)
	}
	if got != string(want) {
		t.Fatalf("librechat.yaml diverges from %s.\n--- got ---\n%s\n--- want ---\n%s", path, got, string(want))
	}
}

// librechatConfigStep returns the librechat recipe's post_start step that
// writes /opt/lc/librechat.yaml — the one #1728 touches — read straight out of
// the embedded recipe catalog, not a copy-pasted literal, so this test fails
// the moment the shipped recipe and the test fixture disagree.
func librechatConfigStep(t *testing.T) string {
	t.Helper()
	r, err := recipes.GetDefault().Get("librechat")
	if err != nil {
		t.Fatalf("load librechat recipe: %v", err)
	}
	for _, step := range r.PostStart {
		if strings.Contains(step, "/opt/lc/librechat.yaml") && strings.Contains(step, "endpoints:") {
			return step
		}
	}
	t.Fatal("librechat recipe: no post_start step writes /opt/lc/librechat.yaml with an endpoints block")
	return ""
}

// runLibreChatConfigStep executes the librechat.yaml-writing post_start step
// in a throwaway temp file (never the real /opt/lc path — this is a unit
// test, not a box) with the given env, and returns the file's bytes. Only
// bash builtins (test, printf, echo) are needed, so this runs with no PATH.
func runLibreChatConfigStep(t *testing.T, env map[string]string) string {
	t.Helper()
	step := librechatConfigStep(t)
	out := filepath.Join(t.TempDir(), "librechat.yaml")
	script := strings.ReplaceAll(step, "/opt/lc/librechat.yaml", out)

	cmd := exec.Command("bash", "-c", script)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("post_start step failed: %v\n%s", err, combined)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read rendered librechat.yaml: %v", err)
	}
	return string(got)
}

// TestLibreChatPostStart_GeminiDefault_Golden: inference_provider unset is the
// pre-#1728 shape — the Gemini endpoint block byte-identical to today's,
// proving the default path's behavior is unchanged. This is the regression
// guard the whole issue rests on: everything else here is new surface, but
// this fixture existed before it and must not move.
func TestLibreChatPostStart_GeminiDefault_Golden(t *testing.T) {
	got := runLibreChatConfigStep(t, map[string]string{
		"CONTAINARIUM_MODEL_GATEWAY_URL": "http://10.0.0.1:8080/v1/model/gemini-openai",
		"CONTAINARIUM_GATEWAY_TOKEN":     "test-gateway-token",
	})
	librechatGolden(t, "librechat-gemini.yaml.golden", got)
}

// TestLibreChatPostStart_GeminiExplicit_Golden: inference_provider explicitly
// set to "gemini-openai" (the recipe's own default provider name) must render
// byte-identically to the unset case — an explicit no-op, not a different
// path.
func TestLibreChatPostStart_GeminiExplicit_Golden(t *testing.T) {
	got := runLibreChatConfigStep(t, map[string]string{
		"CONTAINARIUM_MODEL_GATEWAY_URL":        "http://10.0.0.1:8080/v1/model/gemini-openai",
		"CONTAINARIUM_GATEWAY_TOKEN":            "test-gateway-token",
		"CONTAINARIUM_PARAM_INFERENCE_PROVIDER": "gemini-openai",
	})
	librechatGolden(t, "librechat-gemini.yaml.golden", got)
}

// TestLibreChatPostStart_CustomProvider_Golden: a non-default,
// OpenAI-compatible inference_provider renders the generic `custom` endpoint
// from contract C3 (design doc "workspace on your own inference key",
// component 4) — apiKey left for LibreChat to expand from its own env,
// baseURL the resolved gateway URL, fetch: true so the model list comes from
// the gateway instead of a literal list.
func TestLibreChatPostStart_CustomProvider_Golden(t *testing.T) {
	got := runLibreChatConfigStep(t, map[string]string{
		"CONTAINARIUM_MODEL_GATEWAY_URL":        "http://10.0.0.1:8080/v1/model/openai",
		"CONTAINARIUM_GATEWAY_TOKEN":            "test-gateway-token",
		"CONTAINARIUM_PARAM_INFERENCE_PROVIDER": "openai",
	})
	librechatGolden(t, "librechat-custom-provider.yaml.golden", got)
	if !strings.Contains(got, `fetch: true`) {
		t.Errorf("custom endpoint missing models.fetch=true: %s", got)
	}
	if !strings.Contains(got, `apiKey: "${CTN_GATEWAY_TOKEN}"`) {
		t.Errorf("custom endpoint missing the seeded gateway token apiKey: %s", got)
	}
	if strings.Contains(got, "Gemini") || strings.Contains(got, "gemini-2.5") {
		t.Errorf("custom endpoint should carry no hard-coded Gemini model list: %s", got)
	}
}

// TestLibreChatPostStart_NoGatewaySeeded_Golden: no CONTAINARIUM_MODEL_GATEWAY_URL
// / _GATEWAY_TOKEN at all (no key for org/provider, or self-hosted with no
// gateway configured) — the pre-existing degrade: an empty config, never a
// real key, and inference_provider makes no difference to this branch.
func TestLibreChatPostStart_NoGatewaySeeded_Golden(t *testing.T) {
	got := runLibreChatConfigStep(t, map[string]string{
		"CONTAINARIUM_PARAM_INFERENCE_PROVIDER": "openai",
	})
	librechatGolden(t, "librechat-no-gateway.yaml.golden", got)
	if strings.Contains(got, "apiKey") || strings.Contains(got, "endpoints") {
		t.Errorf("unconfigured box must carry no endpoint/key config at all: %s", got)
	}
}
