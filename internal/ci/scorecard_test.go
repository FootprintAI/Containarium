package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Scorecard publishes from a privileged job. These guards prevent a later
// workflow edit from exposing its token to PR code or invalidating publication.
type scorecardWorkflow struct {
	On          map[string]yaml.Node    `yaml:"on"`
	Permissions map[string]string       `yaml:"permissions"`
	Env         yaml.Node               `yaml:"env"`
	Defaults    yaml.Node               `yaml:"defaults"`
	Jobs        map[string]scorecardJob `yaml:"jobs"`
}

type scorecardJob struct {
	RunsOn      string            `yaml:"runs-on"`
	Permissions map[string]string `yaml:"permissions"`
	Env         yaml.Node         `yaml:"env"`
	Defaults    yaml.Node         `yaml:"defaults"`
	Container   yaml.Node         `yaml:"container"`
	Services    yaml.Node         `yaml:"services"`
	Steps       []scorecardStep   `yaml:"steps"`
}

type scorecardStep struct {
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
}

func loadScorecardWorkflow(t *testing.T) scorecardWorkflow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(workflowDir, "scorecard.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf scorecardWorkflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

func TestScorecardTrustedTriggers(t *testing.T) {
	wf := loadScorecardWorkflow(t)
	if len(wf.On) != 2 {
		t.Fatal("Scorecard must run only on main pushes and the weekly schedule")
	}
	var push triggerFilter
	pushNode := wf.On["push"]
	if err := pushNode.Decode(&push); err != nil {
		t.Fatal(err)
	}
	if len(push.Branches) != 1 || push.Branches[0] != "main" || len(push.Paths) != 0 || len(push.Tags) != 0 {
		t.Error("every main push must run Scorecard, without path or tag filters")
	}
	var schedule []struct {
		Cron string `yaml:"cron"`
	}
	scheduleNode := wf.On["schedule"]
	if err := scheduleNode.Decode(&schedule); err != nil {
		t.Fatal(err)
	}
	if len(schedule) != 1 || !regexp.MustCompile(`^[0-5]?\d [0-2]?\d \* \* [0-6]$`).MatchString(schedule[0].Cron) {
		t.Error("Scorecard must have a weekly schedule")
	}
}

func TestScorecardBadge(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	want := "[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/FootprintAI/Containarium/badge)](https://scorecard.dev/viewer/?uri=github.com/FootprintAI/Containarium)"
	if !strings.Contains(string(b), want) {
		t.Error("README must link the upstream repository's published Scorecard badge")
	}
}

func TestScorecardPublicationBoundary(t *testing.T) {
	wf := loadScorecardWorkflow(t)
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Error("workflow token must default to contents: read")
	}
	if wf.Env.Kind != 0 || wf.Defaults.Kind != 0 {
		t.Error("Scorecard publication forbids workflow env/defaults")
	}
	job, ok := wf.Jobs["analysis"]
	if !ok {
		t.Fatal("missing Scorecard analysis job")
	}
	if !strings.HasPrefix(job.RunsOn, "ubuntu-") {
		t.Error("Scorecard must use a GitHub-hosted Ubuntu runner")
	}
	if job.Env.Kind != 0 || job.Defaults.Kind != 0 || job.Container.Kind != 0 || job.Services.Kind != 0 {
		t.Error("Scorecard publication forbids job env/defaults/containers/services")
	}
	for name, access := range job.Permissions {
		if access == "write" && name != "security-events" && name != "id-token" {
			t.Errorf("unexpected job write permission: %s", name)
		}
	}
	if job.Permissions["contents"] != "read" || job.Permissions["security-events"] != "write" {
		t.Error("analysis needs contents: read and security-events: write")
	}
	for name, other := range wf.Jobs {
		if name != "analysis" && other.Permissions["id-token"] == "write" {
			t.Errorf("only the Scorecard job may mint an OIDC token: %s", name)
		}
	}
	allowed := map[string]bool{
		"actions/checkout": true, "ossf/scorecard-action": true,
		"actions/upload-artifact": true, "github/codeql-action/upload-sarif": true,
	}
	seen := map[string]scorecardStep{}
	for _, step := range job.Steps {
		action, pin, found := strings.Cut(step.Uses, "@")
		if step.Run != "" || !found || !allowed[action] {
			t.Errorf("privileged analysis may only invoke approved actions: %q", step.Uses)
		}
		if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(pin) {
			t.Errorf("action must be pinned to a full SHA: %s", step.Uses)
		}
		seen[action] = step
	}
	for action := range allowed {
		if _, ok := seen[action]; !ok {
			t.Errorf("missing %s", action)
		}
	}
	if seen["actions/checkout"].With["persist-credentials"] != "false" {
		t.Error("checkout must not persist the privileged job's token")
	}
	scan := seen["ossf/scorecard-action"]
	if scan.With["results_format"] != "sarif" || scan.With["results_file"] == "" {
		t.Error("Scorecard must produce a SARIF report")
	}
	if scan.With["repo_token"] != "" {
		t.Error("Scorecard must use its default token, not a new PAT secret")
	}
	if scan.With["publish_results"] != "true" {
		t.Error("Scorecard must publish results to update the badge")
	}
	if job.Permissions["id-token"] != "write" {
		t.Error("publishing the badge requires job-scoped OIDC")
	}
	if seen["github/codeql-action/upload-sarif"].With["sarif_file"] != scan.With["results_file"] ||
		seen["actions/upload-artifact"].With["path"] != scan.With["results_file"] {
		t.Error("code scanning and the public artifact must publish the scan's report")
	}
}
