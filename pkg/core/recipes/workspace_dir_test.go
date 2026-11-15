package recipes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The slides-agent recipe declares its workspace so the daemon can place it
// in the run user's home and report the path (#3679).
func TestSlidesAgentRecipe_DeclaresWorkspaceDir(t *testing.T) {
	r, err := GetDefault().Get("slides-agent")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.GetWorkspaceDir(); got != "slides" {
		t.Errorf("slides-agent workspace_dir = %q, want slides", got)
	}
}

func TestWorkspaceDirValidation(t *testing.T) {
	const boxUser = `
    parameters:
      - name: box_user
        label: Box user
        type: string
        default: ubuntu`
	for _, tc := range []struct {
		name, dir, params string
		wantErr           bool
	}{
		{"plain name", "slides", boxUser, false},
		{"absolute", "/srv/slides", boxUser, true},
		{"parent", "..", boxUser, true},
		{"nested escape", "a/../../b", boxUser, true},
		{"shell metacharacter", "sl$ides", boxUser, true},
		{"no box_user parameter", "slides", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := "recipes:\n  - id: ws\n    image: x\n    workspace_dir: '" + tc.dir + "'" + tc.params + "\n"
			err := New().LoadFromBytes([]byte(y))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestSlidesAgentRecipe_WorkspaceOwnedByWorkspaceUser runs the recipe's
// workspace step with stand-ins for id, chown and podman: the workspace is the
// path the daemon exported, chowned to the user the daemon exported, and the
// container runs as that user with the workspace bind-mounted (#3679). With a
// run user configured that user is the run user; without one, the box user.
func TestSlidesAgentRecipe_WorkspaceOwnedByWorkspaceUser(t *testing.T) {
	r, err := GetDefault().Get("slides-agent")
	if err != nil {
		t.Fatal(err)
	}
	var step string
	for _, line := range r.PostStart {
		if strings.Contains(line, "podman run -d --name slides-agent") {
			step = line
		}
	}
	if step == "" {
		t.Fatal("slides-agent post_start has no workspace step")
	}
	for _, tc := range []struct {
		name, user, uid, home string
	}{
		{"run user configured", "ctn-run", "1001", "home/ctn-run"},
		{"no run user", "ubuntu", "1000", "home/ubuntu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.MkdirAll(bin, 0o750); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "calls.log")
			stubs := map[string]string{
				// id -u/-g <user>: a uid per user, so the test sees whose it is.
				"id":     "#!/bin/sh\ncase \"$2\" in ctn-run) echo 1001;; ubuntu) echo 1000;; *) echo \"no such user $2\" >&2; exit 1;; esac\n",
				"chown":  "#!/bin/sh\necho \"chown $*\" >> \"$CALLS\"\n",
				"podman": "#!/bin/sh\necho \"podman $*\" >> \"$CALLS\"\n",
			}
			for name, body := range stubs {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // test stand-in
					t.Fatal(err)
				}
			}
			ws := filepath.Join(dir, tc.home, "slides")
			cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+step) //nolint:gosec // embedded recipe text
			cmd.Env = append(os.Environ(),
				"PATH="+bin+":"+os.Getenv("PATH"),
				"CALLS="+log,
				"IMAGE=example.invalid/slides:test",
				// The box user stays ubuntu in both cases: only the daemon's
				// workspace exports say who owns the workspace.
				"CONTAINARIUM_PARAM_BOX_USER=ubuntu",
				"BOX_HOME="+filepath.Join(dir, "home/ubuntu"),
				"CONTAINARIUM_WORKSPACE_USER="+tc.user,
				"CONTAINARIUM_WORKSPACE_PATH="+ws,
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("workspace step failed: %v\n%s", err, out)
			}
			if fi, err := os.Stat(ws); err != nil || !fi.IsDir() {
				t.Fatalf("workspace %s not created: %v", ws, err)
			}
			calls, _ := os.ReadFile(log)
			for _, want := range []string{
				"chown -h " + tc.uid + ":" + tc.uid + " " + ws + "\n",
				"--user " + tc.uid + ":" + tc.uid,
				"-v " + ws + ":/workspace",
			} {
				if !strings.Contains(string(calls), want) {
					t.Errorf("missing %q in calls:\n%s", want, calls)
				}
			}
		})
	}
}
