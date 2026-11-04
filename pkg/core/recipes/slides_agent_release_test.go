package recipes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/version"
)

// #3542: the slides-agent image is coupled to the recipe and daemon that run
// its post_start, not to whatever `release` a caller pins for agent-box and
// the skills bundle. These tests run the recipe's image step with a fake
// podman and pin which reference it pulls.

const slidesAgentImageBase = "ghcr.io/footprintai/containarium-slides-agent"

// slidesImageStep is the slides-agent post_start step that chooses and pulls
// the image.
func slidesImageStep(t *testing.T) string {
	t.Helper()
	r, err := GetDefault().Get("slides-agent")
	if err != nil {
		t.Fatal(err)
	}
	var step string
	for _, line := range r.PostStart {
		if strings.Contains(line, "podman pull") {
			if step != "" {
				t.Fatal("slides-agent has more than one podman pull step")
			}
			step = line
		}
	}
	if step == "" {
		t.Fatal("slides-agent post_start has no podman pull step")
	}
	return step
}

type slidesPull struct {
	pulled string // the reference podman was asked to pull, "" if not called
	out    string
	ok     bool
}

// runSlidesImageStep runs the step the way the daemon does (set -euo
// pipefail, parameters and the daemon's own env exported) against a fake
// podman that records what it pulls and exits pullExit.
func runSlidesImageStep(t *testing.T, env map[string]string, pullExit string) slidesPull {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "pulled")
	fake := "#!/bin/sh\n[ \"$1\" = pull ] && printf '%s' \"$2\" > " + record + "\nexit " + pullExit + "\n"
	if err := os.WriteFile(filepath.Join(bin, "podman"), []byte(fake), 0o700); err != nil { //nolint:gosec // test stand-in
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+slidesImageStep(t)+"\necho \"IMAGE=$IMAGE\"") //nolint:gosec // embedded recipe text
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	pulled, _ := os.ReadFile(record) // absent when podman was never called
	return slidesPull{pulled: string(pulled), out: string(out), ok: err == nil}
}

// TestSlidesAgentImage_DefaultsToDaemonRelease: with no slides_image, the
// image tag is the release of the daemon running the recipe — derived from
// the daemon's version, exported as ReleaseEnvName — and the caller's
// `release` parameter has no say in it.
func TestSlidesAgentImage_DefaultsToDaemonRelease(t *testing.T) {
	daemon := version.ReleaseTag()
	if daemon != "v"+version.GetVersion() {
		t.Fatalf("this build's version %q is not a release version; the test needs one", version.GetVersion())
	}
	want := slidesAgentImageBase + ":" + daemon
	for _, callerRelease := range []string{"", "v0.1.0", "v0.125.0", daemon} {
		got := runSlidesImageStep(t, map[string]string{
			ReleaseEnvName:               daemon,
			ParamEnvName("release"):      callerRelease,
			ParamEnvName("slides_image"): "",
		}, "0")
		if !got.ok || got.pulled != want {
			t.Errorf("release=%q: pulled %q (ok=%v), want %q\n%s", callerRelease, got.pulled, got.ok, want, got.out)
		}
		// The later steps run what was pulled.
		if !strings.Contains(got.out, "IMAGE="+want+"\n") {
			t.Errorf("release=%q: IMAGE is not the pulled reference\n%s", callerRelease, got.out)
		}
	}
}

// TestSlidesAgentImage_SlidesImageOverrides: slides_image still wins, for a
// mirror or a rehearsal build, whatever the daemon's release.
func TestSlidesAgentImage_SlidesImageOverrides(t *testing.T) {
	const mirror = "registry.example.invalid/mirror/slides-agent:rehearsal"
	for _, daemon := range []string{"v9.9.9", ""} {
		got := runSlidesImageStep(t, map[string]string{
			ReleaseEnvName:               daemon,
			ParamEnvName("release"):      "v0.1.0",
			ParamEnvName("slides_image"): mirror,
		}, "0")
		if !got.ok || got.pulled != mirror {
			t.Errorf("daemon release %q: pulled %q (ok=%v), want the override %q\n%s", daemon, got.pulled, got.ok, mirror, got.out)
		}
	}
}

// TestSlidesAgentImage_NoDaemonReleaseRefuses: a daemon build that reports no
// release tag has no published image to default to. The step refuses before
// pulling, names slides_image, and never falls back to the caller's release.
func TestSlidesAgentImage_NoDaemonReleaseRefuses(t *testing.T) {
	for _, env := range []map[string]string{
		{ReleaseEnvName: "", ParamEnvName("release"): "v0.126.0", ParamEnvName("slides_image"): ""},
		{ParamEnvName("release"): "v0.126.0", ParamEnvName("slides_image"): ""}, // not exported at all
	} {
		got := runSlidesImageStep(t, env, "0")
		if got.ok || got.pulled != "" {
			t.Errorf("%v: ok=%v pulled %q, want a refusal before any pull\n%s", env, got.ok, got.pulled, got.out)
		}
		if !strings.Contains(got.out, "slides_image") {
			t.Errorf("%v: the refusal should name slides_image:\n%s", env, got.out)
		}
	}
}

// TestSlidesAgentImage_FailedPullFailsTheStep: a pull that fails (a tag that
// was never published) fails the step, naming the reference.
func TestSlidesAgentImage_FailedPullFailsTheStep(t *testing.T) {
	got := runSlidesImageStep(t, map[string]string{
		ReleaseEnvName:               "v9.9.9",
		ParamEnvName("release"):      "v9.9.9",
		ParamEnvName("slides_image"): "",
	}, "125")
	if got.ok {
		t.Fatalf("a failed pull must fail the step\n%s", got.out)
	}
	if !strings.Contains(got.out, slidesAgentImageBase+":v9.9.9") {
		t.Errorf("the failure should name the image it could not pull:\n%s", got.out)
	}
}

// TestDaemonReleaseOnlyGovernsTheSlidesImage: `release` keeps governing what
// it governs today. Only slides-agent's image step reads the daemon's
// release; every other step of every recipe — coding-agent's agent-box and
// skills steps, which slides-agent shares — still reads the caller's
// `release`, which stays required with no default.
func TestDaemonReleaseOnlyGovernsTheSlidesImage(t *testing.T) {
	image := slidesImageStep(t)
	for _, r := range GetDefault().List() {
		for _, line := range r.PostStart {
			if strings.Contains(line, ReleaseEnvName) && line != image {
				t.Errorf("recipe %s: step %.60q reads %s; only the slides-agent image step may", r.Id, line, ReleaseEnvName)
			}
		}
	}
	if strings.Contains(image, ParamEnvName("release")) {
		t.Error("the slides image step must not read the caller's release parameter")
	}
	for _, id := range []string{"coding-agent", "slides-agent"} {
		r, err := GetDefault().Get(id)
		if err != nil {
			t.Fatal(err)
		}
		var release bool
		for _, p := range r.Parameters {
			if p.Name == "release" {
				release = true
				if !p.Required || p.Default != "" {
					t.Errorf("%s: release must stay required with no default; got %+v", id, p)
				}
			}
		}
		if !release {
			t.Errorf("%s: no release parameter", id)
		}
		var readsRelease bool
		for _, line := range r.PostStart {
			if strings.Contains(line, "$"+ParamEnvName("release")) {
				readsRelease = true
			}
		}
		if !readsRelease {
			t.Errorf("%s: agent-box and the skills bundle must still come from the caller's release", id)
		}
	}
}
