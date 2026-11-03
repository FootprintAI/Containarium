package recipes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The agent-runtime recipe's opt-in toolchains parameter (#3491). Empty is
// today's box exactly; python adds the Python toolchain; anything else fails
// provisioning before the box installs anything.

func agentRuntimeRecipe(t *testing.T) *pb.Recipe {
	t.Helper()
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	r, err := m.Get("agent-runtime")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// toolchainSteps returns the post_start index of the validation step, of the
// python install step and of the in-box loop assembly step.
func toolchainSteps(t *testing.T, r *pb.Recipe) (validate, python, assembly int) {
	t.Helper()
	validate, python, assembly = -1, -1, -1
	for i, line := range r.PostStart {
		switch {
		case strings.Contains(line, "CONTAINARIUM_PARAM_TOOLCHAINS") && strings.Contains(line, "unsupported toolchain"):
			validate = i
		case strings.Contains(line, "CONTAINARIUM_PARAM_TOOLCHAINS") && strings.Contains(line, "python3-venv"):
			python = i
		case strings.Contains(line, "install-agent-runtime.sh"):
			assembly = i
		}
	}
	if validate < 0 || python < 0 || assembly < 0 {
		t.Fatalf("agent-runtime post_start lacks a step: validate=%d python=%d assembly=%d", validate, python, assembly)
	}
	return validate, python, assembly
}

func TestAgentRuntimeRecipe_ToolchainsParam(t *testing.T) {
	r := agentRuntimeRecipe(t)
	var param *pb.RecipeParam
	for _, p := range r.Parameters {
		if p.Name == "toolchains" {
			param = p
		}
	}
	if param == nil {
		t.Fatal("agent-runtime missing parameter toolchains")
	}
	if param.Required || param.Default != "" {
		t.Errorf("toolchains must be optional with an empty default (empty = today's box); got required=%v default=%q", param.Required, param.Default)
	}
	if !strings.Contains(param.Description, "python") {
		t.Errorf("toolchains description does not name the supported value: %q", param.Description)
	}
	// Resolution exports it even when unset, so post_start always sees it.
	got, err := ResolveParameters(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := got["toolchains"]; !ok || v != "" {
		t.Errorf("resolved toolchains = %q (present=%v), want empty and present", v, ok)
	}
}

// Validation is the first thing post_start does, so an unknown toolchain
// fails before any download; the python step runs after the assembly that
// installs the agent-python helper it checks for.
func TestAgentRuntimeRecipe_ToolchainStepOrder(t *testing.T) {
	validate, python, assembly := toolchainSteps(t, agentRuntimeRecipe(t))
	if validate != 0 {
		t.Errorf("toolchains validation is post_start step %d, want 0", validate)
	}
	if python < assembly {
		t.Errorf("python toolchain step %d runs before the assembly step %d that ships agent-python", python, assembly)
	}
}

// TestAgentRuntimeRecipe_ToolchainSteps runs the two toolchain steps the way
// the daemon does (one bash script under set -euo pipefail, parameters
// exported) against a stub apt-get.
func TestAgentRuntimeRecipe_ToolchainSteps(t *testing.T) {
	r := agentRuntimeRecipe(t)
	validate, python, _ := toolchainSteps(t, r)
	steps := r.PostStart[validate] + "\n" + r.PostStart[python] + "\n"

	for _, tc := range []struct {
		name, value   string
		helper        bool // agent-python on PATH
		aptFails      bool
		wantOK        bool
		wantApt       bool
		wantErrSubstr []string
	}{
		{name: "empty is today's box", value: "", helper: true, wantOK: true},
		{name: "python", value: "python", helper: true, wantOK: true, wantApt: true},
		{name: "spaces and repeats", value: " python , python", helper: true, wantOK: true, wantApt: true},
		{name: "unknown", value: "ruby", helper: true, wantErrSubstr: []string{`unsupported toolchain "ruby"`, "supported: python"}},
		{name: "unknown beside python fails before installing", value: "python,ruby", helper: true, wantErrSubstr: []string{`"ruby"`}},
		{name: "a glob is a value, not a file list", value: "*", helper: true, wantErrSubstr: []string{`unsupported toolchain "*"`}},
		{name: "case matters", value: "Python", helper: true, wantErrSubstr: []string{`"Python"`}},
		{name: "helper missing", value: "python", helper: false, wantApt: true, wantErrSubstr: []string{"agent-python"}},
		{name: "apt failure", value: "python", helper: true, aptFails: true, wantApt: true, wantErrSubstr: []string{"python toolchain"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "apt-calls")
			code := "0"
			if tc.aptFails {
				code = "100"
			}
			stub := map[string]string{"apt-get": "#!/bin/sh\necho \"$*\" >> " + calls + "\nexit " + code + "\n"}
			if tc.helper {
				stub["agent-python"] = "#!/bin/sh\nexit 0\n"
			}
			for name, body := range stub {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { //nolint:gosec // test stand-in
					t.Fatal(err)
				}
			}
			script := "set -euo pipefail\nexport CONTAINARIUM_PARAM_TOOLCHAINS=" + shellQuoteForTest(tc.value) + "\n" + steps
			cmd := exec.Command("bash", "-c", script) //nolint:gosec // embedded recipe text
			cmd.Dir = dir                             // a glob would expand against the stubs here
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("ok=%v, want %v\n%s", err == nil, tc.wantOK, out)
			}
			for _, want := range tc.wantErrSubstr {
				if !strings.Contains(string(out), want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			got, _ := os.ReadFile(calls) //nolint:gosec // test temp file
			if tc.wantApt != (len(got) > 0) {
				t.Errorf("apt-get called=%v, want %v: %s", len(got) > 0, tc.wantApt, got)
			}
			if tc.wantApt && !tc.aptFails {
				for _, pkg := range []string{"python3-venv", "python3-pip", "python3-pytest"} {
					if !strings.Contains(string(got), pkg) {
						t.Errorf("apt-get install lacks %s: %s", pkg, got)
					}
				}
			}
		})
	}
}

func shellQuoteForTest(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
