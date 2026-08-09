// Package ci holds guards over this repo's CI configuration itself.
//
// The workflows decide whether anything else in the repo is checked at all,
// so a mistake in them is invisible in exactly the way a mistake in normal
// code is not: nothing goes red, a check simply stops existing.
package ci

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const workflowDir = "../../.github/workflows"

// workflowFile models only the trigger section — the rest of a workflow is
// not this test's business.
//
// `on` is decoded as raw nodes rather than a struct because the distinction
// this whole file turns on is *key present but empty* vs *key absent*:
//
//	pull_request:              # present, unfiltered — gates every PR
//	pull_request:              # present, filtered — gates only some
//	  branches: [main]
//	(no pull_request key)      # absent — gates nothing
//
// A bare `pull_request:` is YAML null, so decoding into a *struct pointer
// yields nil and makes the first case indistinguishable from the third. The
// first draft of this test did exactly that and passed vacuously for the
// three workflows it was written to protect.
type workflowFile struct {
	Name string               `yaml:"name"`
	On   map[string]yaml.Node `yaml:"on"`
}

type triggerFilter struct {
	Branches []string `yaml:"branches"`
	Paths    []string `yaml:"paths"`
	Tags     []string `yaml:"tags"`
	Types    []string `yaml:"types"`
}

// trigger returns the named trigger's filters and whether the key is present
// at all. A present-but-empty trigger returns a zero filter and true.
func (w workflowFile) trigger(t *testing.T, name string) (triggerFilter, bool) {
	t.Helper()
	node, ok := w.On[name]
	if !ok {
		return triggerFilter{}, false
	}
	// Null (bare `pull_request:`) — present, no filters, gates everything.
	if node.Kind == 0 || node.Tag == "!!null" {
		return triggerFilter{}, true
	}
	var f triggerFilter
	if err := node.Decode(&f); err != nil {
		t.Fatalf("decode %s trigger in %s: %v", name, w.Name, err)
	}
	return f, true
}

func loadWorkflows(t *testing.T) map[string]workflowFile {
	t.Helper()
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("read %s: %v", workflowDir, err)
	}

	out := map[string]workflowFile{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(workflowDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var wf workflowFile
		if err := yaml.Unmarshal(b, &wf); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out[name] = wf
	}
	if len(out) == 0 {
		t.Fatal("no workflow files found — this guard would pass vacuously")
	}
	return out
}

// A base-branch filter on pull_request means a PR targeting anything other
// than main gets ZERO checks — not failing, not pending, absent. `gh pr
// checks` reports "no checks reported on the branch" and the PR page shows
// no status section at all.
//
// That is the dangerous shape: an unchecked PR is visually identical to one
// whose checks haven't started, so the natural reading is "wait a moment"
// and the natural next step is to merge. Main-branch protection is no
// backstop, because a stacked PR by definition doesn't merge into main, so
// the required-checks rule never engages for it (#1215).
//
// Retargeting the PR at main afterwards does not help either: changing a
// PR's base does not re-fire `pull_request` (the `edited` activity type
// isn't in the default trigger set), so a retargeted PR stays ungated until
// it is closed and reopened.
func TestPullRequestTriggersAreNotBaseFiltered(t *testing.T) {
	var offenders []string

	for name, wf := range loadWorkflows(t) {
		pr, present := wf.trigger(t, "pull_request")
		if !present {
			continue // not a PR-gating workflow; push/tag/schedule only
		}
		if len(pr.Branches) > 0 {
			offenders = append(offenders,
				name+" (branches: "+strings.Join(pr.Branches, ", ")+")")
		}
	}

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("these workflows filter pull_request by base branch, so any PR not targeting "+
			"that branch runs NONE of them and shows no checks at all (#1215):\n  %s\n"+
			"Drop the `branches:` filter under `pull_request:`. Keep it under `push:` — "+
			"that one is what stops branch pushes double-running alongside the PR.",
			strings.Join(offenders, "\n  "))
	}
}

// The counterpart: `push` SHOULD stay pinned, otherwise every push to every
// branch runs the full suite a second time alongside the PR's own run. The
// fix for #1215 is to unfilter one trigger, not both.
func TestPushTriggersStayPinnedToMain(t *testing.T) {
	for name, wf := range loadWorkflows(t) {
		push, present := wf.trigger(t, "push")
		if !present {
			continue
		}
		// Tag-triggered release workflows legitimately have no branch filter.
		if len(push.Tags) > 0 {
			continue
		}
		if len(push.Branches) == 0 {
			t.Errorf("%s: `push` has no branches filter, so every push to every branch "+
				"runs it again alongside the PR's own run", name)
		}
	}
}

// A workflow with no pull_request trigger at all contributes nothing to PR
// gating. That can be correct (release/tag workflows), so this only reports
// what the set is — it exists so a reviewer can see at a glance which
// workflows do and don't gate a PR, rather than inferring it from 13 files.
func TestReportWorkflowGatingCoverage(t *testing.T) {
	var gating, notGating []string
	for name, wf := range loadWorkflows(t) {
		pr, present := wf.trigger(t, "pull_request")
		if !present {
			notGating = append(notGating, name)
			continue
		}
		suffix := ""
		if len(pr.Paths) > 0 {
			suffix = " (path-scoped)"
		}
		gating = append(gating, name+suffix)
	}
	sort.Strings(gating)
	sort.Strings(notGating)
	t.Logf("gate PRs (%d): %s", len(gating), strings.Join(gating, ", "))
	t.Logf("do not gate PRs (%d): %s", len(notGating), strings.Join(notGating, ", "))
}
