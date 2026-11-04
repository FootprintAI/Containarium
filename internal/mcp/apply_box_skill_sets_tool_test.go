package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// #3511: apply_box_skill_sets is a thin wrapper over the client function
// `containarium code skill-sets` calls, over the same REST path.

func TestApplyBoxSkillSetsTool_AppliesAndReports(t *testing.T) {
	var path, method string
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, method = r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = w.Write([]byte(`{"skillSets":["qa","sdlc"],"installed":[{"skillSet":"qa","skills":["qa-sprint-verify"]}],` +
			`"removed":[{"skillSet":"old","skills":["old-skill"]}],"unchanged":false,"release":"v0.89.0"}`))
	}))
	defer srv.Close()

	out, err := handleApplyBoxSkillSets(NewClient(srv.URL, "tok"), map[string]interface{}{
		"box": "alice", "skill_sets": []interface{}{"sdlc", "qa"}, "release": "v0.89.0",
	})
	if err != nil {
		t.Fatalf("handleApplyBoxSkillSets: %v", err)
	}
	if method != http.MethodPost || path != "/v1/containers/alice/skill-sets:apply" {
		t.Errorf("request = %s %s", method, path)
	}
	if body["release"] != "v0.89.0" {
		t.Errorf("body = %v", body)
	}
	for _, want := range []string{"alice", "installed qa: qa-sprint-verify", "removed old: old-skill", "v0.89.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestApplyBoxSkillSetsTool_UnchangedAndEmptyRemovesAll(t *testing.T) {
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = w.Write([]byte(`{"skillSets":[],"unchanged":true,"release":"v0.89.0"}`))
	}))
	defer srv.Close()
	out, err := handleApplyBoxSkillSets(NewClient(srv.URL, "tok"), map[string]interface{}{
		"box": "alice", "skill_sets": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "unchanged") {
		t.Errorf("output = %q", out)
	}
	if sets, _ := body["skillSets"].([]interface{}); len(sets) != 0 {
		t.Errorf("an empty array must reach the daemon as an empty target, body = %v", body)
	}
}

func TestApplyBoxSkillSetsTool_TypedRefusalCarriesReason(t *testing.T) {
	for _, reason := range []string{"RUN_IN_PROGRESS", "SET_PREDATES_MANIFEST"} {
		t.Run(reason, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":9,"message":"daemon words","details":[{"@type":"type.googleapis.com/google.rpc.PreconditionFailure","violations":[{"type":"BOX_SKILL_SETS_REFUSAL_` + reason + `","subject":"alice"}]}]}`))
			}))
			defer srv.Close()
			_, err := handleApplyBoxSkillSets(NewClient(srv.URL, "tok"), map[string]interface{}{
				"box": "alice", "skill_sets": []interface{}{"qa"},
			})
			if err == nil || !strings.Contains(err.Error(), "refused ("+reason+")") || !strings.Contains(err.Error(), "daemon words") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("UNKNOWN_SKILL_SET", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":3,"message":"unknown set nope","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"skill_sets","reason":"BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET"}]}]}`))
		}))
		defer srv.Close()
		_, err := handleApplyBoxSkillSets(NewClient(srv.URL, "tok"), map[string]interface{}{
			"box": "alice", "skill_sets": []interface{}{"nope"},
		})
		if err == nil || !strings.Contains(err.Error(), "refused (UNKNOWN_SKILL_SET)") {
			t.Fatalf("err = %v", err)
		}
	})
}

// Invalid input is rejected before any request is made: the server fails the
// test if it is reached at all.
func TestApplyBoxSkillSetsTool_InvalidInputSendsNoRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")

	cases := map[string]map[string]interface{}{
		"missing box":        {"skill_sets": []interface{}{"qa"}},
		"bad box name":       {"box": "../etc", "skill_sets": []interface{}{"qa"}},
		"uppercase box":      {"box": "Alice", "skill_sets": []interface{}{"qa"}},
		"bad release":        {"box": "alice", "skill_sets": []interface{}{"qa"}, "release": "v1;rm -rf /"},
		"shell in set id":    {"box": "alice", "skill_sets": []interface{}{"qa;rm -rf /"}},
		"substitution in id": {"box": "alice", "skill_sets": []interface{}{"$(id)"}},
		"comma in set id":    {"box": "alice", "skill_sets": []interface{}{"qa,sdlc"}},
		"all literal":        {"box": "alice", "skill_sets": []interface{}{"all"}},
		"none literal":       {"box": "alice", "skill_sets": []interface{}{"none"}},
		"skill_sets absent":  {"box": "alice"},
		"skill_sets string":  {"box": "alice", "skill_sets": "qa"},
		"non-string id":      {"box": "alice", "skill_sets": []interface{}{float64(3)}},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := handleApplyBoxSkillSets(c, args); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	if requests.Load() != 0 {
		t.Errorf("%d requests were sent", requests.Load())
	}
}

func TestApplyBoxSkillSetsTool_SchemaAndScope(t *testing.T) {
	tool := applyBoxSkillSetsTool()
	props := tool.InputSchema["properties"].(map[string]interface{})
	for _, k := range []string{"box", "skill_sets", "release"} {
		if _, ok := props[k]; !ok {
			t.Errorf("schema has no %s", k)
		}
	}
	if _, ok := props["all"]; ok {
		t.Error("schema has an all argument")
	}
	if got := toolScopeAssignments()["apply_box_skill_sets"]; got != auth.ScopeContainersWrite {
		t.Errorf("scope = %q", got)
	}
	registered := false
	srv := &Server{}
	srv.registerTools()
	for _, tl := range srv.tools {
		if tl.Name == "apply_box_skill_sets" {
			registered = true
		}
	}
	if !registered {
		t.Error("apply_box_skill_sets is not registered")
	}
}
