//go:build !containarium_client

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// writeSkill writes ~/.claude/skills/<dir>/SKILL.md under home, as a person
// installing a skill by hand would.
func writeSkill(t *testing.T, home, dir, content string) {
	t.Helper()
	p := filepath.Join(home, ".claude", "skills", dir)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(p, "SKILL.md"), content)
}

// skillSetRefusalOf returns the typed BoxSkillSetsRefusal err carries in its
// details (a PreconditionFailure violation's type, or a BadRequest field
// violation's reason) and that violation's subject or field, or UNSPECIFIED
// when it carries none.
func skillSetRefusalOf(t *testing.T, err error) (pb.BoxSkillSetsRefusal, string) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		return pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED, ""
	}
	for _, d := range st.Details() {
		switch p := d.(type) {
		case *errdetails.PreconditionFailure:
			if len(p.GetViolations()) != 1 {
				t.Fatalf("want one violation, got %v", p.GetViolations())
			}
			v := p.GetViolations()[0]
			return pb.BoxSkillSetsRefusal(pb.BoxSkillSetsRefusal_value[v.GetType()]), v.GetSubject()
		case *errdetails.BadRequest:
			if len(p.GetFieldViolations()) != 1 {
				t.Fatalf("want one field violation, got %v", p.GetFieldViolations())
			}
			v := p.GetFieldViolations()[0]
			return pb.BoxSkillSetsRefusal(pb.BoxSkillSetsRefusal_value[v.GetReason()]), v.GetField()
		}
	}
	return pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED, ""
}

// Every refusal of ApplyBoxSkillSets carries its reason as a typed detail the
// control plane can switch on, never only as message text (#3374). An unknown
// set id is the caller's mistake (INVALID_ARGUMENT, a BadRequest on the
// skill_sets field); the other two are the box's state (FAILED_PRECONDITION,
// a PreconditionFailure naming the box or the set).
func TestBoxSkillSetsRefusal_CarriesATypedReason(t *testing.T) {
	tests := []struct {
		reason      pb.BoxSkillSetsRefusal
		subject     string
		wantCode    codes.Code
		wantSubject string
	}{
		{pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET, "nope", codes.InvalidArgument, "skill_sets"},
		{pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS, "alice-container", codes.FailedPrecondition, "alice-container"},
		{pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_SET_PREDATES_MANIFEST, "sdlc", codes.FailedPrecondition, "sdlc"},
	}
	for _, tt := range tests {
		t.Run(tt.reason.String(), func(t *testing.T) {
			err := boxSkillSetsRefusal(tt.reason, tt.subject, "why: "+tt.subject)
			if status.Code(err) != tt.wantCode {
				t.Fatalf("code = %v, want %v (%v)", status.Code(err), tt.wantCode, err)
			}
			got, subject := skillSetRefusalOf(t, err)
			if got != tt.reason || subject != tt.wantSubject {
				t.Errorf("typed reason = (%v, %q), want (%v, %q)", got, subject, tt.reason, tt.wantSubject)
			}
			if !strings.Contains(status.Convert(err).Message(), "why: "+tt.subject) {
				t.Errorf("message %q lost the explanation", status.Convert(err).Message())
			}
		})
	}
}

// The typed reason survives the error handler the daemon actually serves
// (gateway.ErrorHandler), which is the form the hosted control plane receives
// (#3277). Both detail shapes are checked, since they travel differently.
func TestBoxSkillSetsRefusal_SurvivesTheRESTGateway(t *testing.T) {
	render := func(t *testing.T, err error) (int, []json.RawMessage) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/containers/alice/skill-sets:apply", nil)
		gateway.ErrorHandler(context.Background(), runtime.NewServeMux(), &runtime.JSONPb{}, w, req, err)
		var body struct {
			Code    int               `json:"code"`
			Details []json.RawMessage `json:"details"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("gateway body is not JSON: %v\n%s", err, w.Body.String())
		}
		if len(body.Details) != 1 {
			t.Fatalf("want one detail:\n%s", w.Body.String())
		}
		return body.Code, body.Details
	}

	t.Run("run in progress", func(t *testing.T) {
		code, details := render(t, boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS, "alice-container", "run \"code\" is running"))
		var d struct {
			Type       string `json:"@type"`
			Violations []struct {
				Type    string `json:"type"`
				Subject string `json:"subject"`
			} `json:"violations"`
		}
		if err := json.Unmarshal(details[0], &d); err != nil {
			t.Fatal(err)
		}
		if code != http.StatusBadRequest || !strings.HasSuffix(d.Type, "google.rpc.PreconditionFailure") || len(d.Violations) != 1 ||
			d.Violations[0].Type != "BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS" || d.Violations[0].Subject != "alice-container" {
			t.Fatalf("typed reason lost in the REST body: code=%d %s", code, details[0])
		}
	})
	t.Run("unknown skill set", func(t *testing.T) {
		code, details := render(t, boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET, "nope", "unknown skill set \"nope\""))
		var d struct {
			Type            string `json:"@type"`
			FieldViolations []struct {
				Field  string `json:"field"`
				Reason string `json:"reason"`
			} `json:"fieldViolations"`
		}
		if err := json.Unmarshal(details[0], &d); err != nil {
			t.Fatal(err)
		}
		if code != http.StatusBadRequest || !strings.HasSuffix(d.Type, "google.rpc.BadRequest") || len(d.FieldViolations) != 1 ||
			d.FieldViolations[0].Reason != "BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET" || d.FieldViolations[0].Field != "skill_sets" {
			t.Fatalf("typed reason lost in the REST body: code=%d %s", code, details[0])
		}
	})
}

// The request's set ids are validated against the lock this daemon was built
// with before anything touches the box: an id the lock does not define is a
// typed UNKNOWN_SKILL_SET naming the known ids; "all" and "none" are the
// installer's literals, not set ids. Duplicates collapse; the result is sorted
// so the manifest and the response are deterministic.
func TestValidateSkillSetIDs(t *testing.T) {
	known := map[string][]string{"sdlc": {"engineer"}, "qa": {"qa"}, "security": {"security"}}
	tests := []struct {
		name    string
		ids     []string
		want    []string
		wantErr bool
		unknown string // the offending id the message must name
	}{
		{"empty is the empty target", nil, nil, false, ""},
		{"known ids, sorted", []string{"security", "sdlc"}, []string{"sdlc", "security"}, false, ""},
		{"duplicates collapse", []string{"qa", "qa"}, []string{"qa"}, false, ""},
		{"an unknown id", []string{"sdlc", "nope"}, nil, true, "nope"},
		{"all is not a set id", []string{"all"}, nil, true, "all"},
		{"none is not a set id", []string{"none"}, nil, true, "none"},
		{"shell syntax is not a set id", []string{"qa;rm -rf /"}, nil, true, "qa;rm -rf /"},
		{"an empty id", []string{""}, nil, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateSkillSetIDs(tt.ids, known)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("ids = %q, want %q", got, tt.want)
				}
				return
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			reason, field := skillSetRefusalOf(t, err)
			if reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET || field != "skill_sets" {
				t.Errorf("typed reason = (%v, %q)", reason, field)
			}
			msg := status.Convert(err).Message()
			for _, k := range []string{"qa", "sdlc", "security"} {
				if !strings.Contains(msg, k) {
					t.Errorf("message %q does not name known set %q", msg, k)
				}
			}
			if tt.unknown != "" && !strings.Contains(msg, tt.unknown) {
				t.Errorf("message %q does not name the offending id %q", msg, tt.unknown)
			}
		})
	}
}

// The RPC's contract gates in order: a malformed owner is INVALID_ARGUMENT, a
// stranger is PermissionDenied, an unknown set id is the typed refusal, a
// malformed release is INVALID_ARGUMENT, all before the box is touched; a
// daemon with no box backend is Unavailable. Nothing was executed in the box
// on any of these paths.
func TestApplyBoxSkillSets_ContractGates(t *testing.T) {
	b := &shBox{}
	s, _ := boxRunServer(t, b)
	s.boxRunStartExec = func(box, _, script string) (string, error) { return b.exec(box, script) }
	if _, err := s.ApplyBoxSkillSets(tenantCtx("alice"), &pb.ApplyBoxSkillSetsRequest{Username: "../x", SkillSets: []string{"qa"}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad username: %v", err)
	}
	if _, err := s.ApplyBoxSkillSets(tenantCtx("mallory"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"qa"}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("stranger: %v", err)
	}
	_, err := s.ApplyBoxSkillSets(tenantCtx("alice"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"qa", "nope"}})
	if reason, _ := skillSetRefusalOf(t, err); status.Code(err) != codes.InvalidArgument || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET {
		t.Errorf("unknown set: %v", err)
	}
	if _, err := s.ApplyBoxSkillSets(tenantCtx("alice"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"qa"}, Release: "v1;rm -rf /"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad release: %v", err)
	}
	if _, err := s.ApplyBoxSkillSets(tenantCtx("bob"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"qa"}}); status.Code(err) != codes.Unavailable {
		t.Errorf("collaborator, well-formed, no box backend: %v, want Unavailable", err)
	}
	if len(b.boxes) != 0 {
		t.Errorf("the contract gates executed %d script(s) in the box", len(b.boxes))
	}
}

// --- the served call (#3374 slice 2) ---------------------------------------
//
// The box scripts run here with the local sh against a temp HOME standing in
// for the box owner's home, and the install step runs the REAL installer
// (scripts/install-sdlc-skills.sh) against a release served from a file://
// base, so what these tests prove about prune and manifest semantics is the
// installer's own behaviour, not a fake's.

const installSDLCSkillsScriptPath = "../../scripts/install-sdlc-skills.sh"

func needSkillInstallTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "tar", "sha256sum"} {
		if _, err := osexec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
}

// skillBundleFixture writes a release's assets — sdlc-skills.tar.gz, its
// .sha256, and a lock whose set lines match the embedded lock's set ids — and
// returns the file:// base and lock URLs the installer reads them from. The
// bundle holds one skill per namespace used below plus _shared.
func skillBundleFixture(t *testing.T) (baseURL, lockURL string) {
	t.Helper()
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"_shared/tracker.md", "architect-design/SKILL.md", "engineer-implement/SKILL.md", "qa-unit-test/SKILL.md", "security-triage/SKILL.md"} {
		body := "# " + name + "\n"
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	sha := hex.EncodeToString(sum[:])
	writeFile(t, filepath.Join(dir, "sdlc-skills.tar.gz"), buf.String())
	writeFile(t, filepath.Join(dir, "sdlc-skills.tar.gz.sha256"), sha+"  sdlc-skills.tar.gz\n")
	lock := filepath.Join(dir, "sdlc-skills.lock")
	writeFile(t, lock, "set.sdlc=architect,engineer\nset.qa=qa\nset.security=security\n[sdlc]\nrepo=example/skills\nref="+strings.Repeat("a", 40)+"\nsha256="+sha+"\n")
	return "file://" + dir, "file://" + lock
}

// skillSetServer is a ContainerServer whose box is a temp home: user scripts
// run with HOME=home, root scripts read run records from the returned log
// dir, and the install step runs the real installer against the fixture
// release. installs counts install invocations.
func skillSetServer(t *testing.T, home string, state pb.ContainerState) (s *ContainerServer, logDir string, installs *int) {
	t.Helper()
	needSkillInstallTools(t)
	base, lock := skillBundleFixture(t)
	b := &shBox{}
	s, logDir = boxRunServer(t, b)
	s.boxRunStartExec = func(_, _, script string) (string, error) {
		cmd := osexec.Command("sh", "-c", script)
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.Output()
		if err != nil {
			if ee, ok := err.(*osexec.ExitError); ok {
				return "", fmt.Errorf("%v: %s", err, ee.Stderr)
			}
			return "", err
		}
		return string(out), nil
	}
	n := 0
	installs = &n
	s.boxSkillSetsInstall = func(_, _, _ string, sets sdlcskills.SkillSets) (string, error) {
		n++
		cmd := osexec.Command("bash", installSDLCSkillsScriptPath)
		cmd.Env = append(os.Environ(), "HOME="+home, "ARTIFACT_BASE_URL="+base, "SDLC_SKILLS_LOCK_URL="+lock, "SKILL_SETS="+sets.String())
		out, err := cmd.CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%v: %s", err, out)
		}
		return string(out), nil
	}
	s.runCheckoutBoxes = func(context.Context) ([]box.BoxStatus, error) {
		return []box.BoxStatus{{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}, State: state}}, nil
	}
	return s, logDir, installs
}

func apply(t *testing.T, s *ContainerServer, sets ...string) (*pb.ApplyBoxSkillSetsResponse, error) {
	t.Helper()
	return s.ApplyBoxSkillSets(tenantCtx("alice"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: sets, Release: "v9.9.9"})
}

func skillDirs(t *testing.T, home string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(home, ".claude", "skills"))
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func readSkillSetManifest(t *testing.T, home string) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".claude", "skills", boxSkillSetsManifestFile))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var m boxSkillSetManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("manifest %s: %v", data, err)
	}
	if m.Version != boxSkillSetManifestVersion || m.Release != "v9.9.9" {
		t.Errorf("manifest header = %+v", m)
	}
	return m.Sets
}

func changes(c []*pb.BoxSkillSetChange) string {
	var parts []string
	for _, x := range c {
		parts = append(parts, x.GetSkillSet()+":"+strings.Join(x.GetSkills(), ","))
	}
	return strings.Join(parts, " ")
}

// Acceptance: adding a set to a running box installs its skills; removing one
// deletes only the skills that set installed; repeating the call changes
// nothing and says so (#3374).
func TestApplyBoxSkillSets_AddRemoveRepeat(t *testing.T) {
	home := t.TempDir()
	s, _, installs := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)

	resp, err := apply(t, s, "qa")
	if err != nil {
		t.Fatal(err)
	}
	if changes(resp.GetInstalled()) != "qa:qa-unit-test" || len(resp.GetRemoved()) != 0 || resp.GetUnchanged() ||
		strings.Join(resp.GetSkillSets(), ",") != "qa" || resp.GetRelease() != "v9.9.9" {
		t.Fatalf("add qa: installed=%q removed=%q unchanged=%v sets=%v release=%q", changes(resp.GetInstalled()), changes(resp.GetRemoved()), resp.GetUnchanged(), resp.GetSkillSets(), resp.GetRelease())
	}
	if got := skillDirs(t, home); strings.Join(got, ",") != "_shared,qa-unit-test" {
		t.Fatalf("dirs = %v", got)
	}
	if m := readSkillSetManifest(t, home); !reflect.DeepEqual(m, map[string][]string{"qa": {"qa-unit-test"}}) {
		t.Fatalf("manifest = %v", m)
	}

	// Repeating the call: nothing installed or removed, and it says so.
	resp, err = apply(t, s, "qa")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetUnchanged() || len(resp.GetInstalled()) != 0 || len(resp.GetRemoved()) != 0 {
		t.Fatalf("repeat: %v", resp)
	}

	// Widening to sdlc too installs sdlc's skills only; qa is not re-reported.
	resp, err = apply(t, s, "qa", "sdlc")
	if err != nil {
		t.Fatal(err)
	}
	if changes(resp.GetInstalled()) != "sdlc:architect-design,engineer-implement" || len(resp.GetRemoved()) != 0 || resp.GetUnchanged() ||
		strings.Join(resp.GetSkillSets(), ",") != "qa,sdlc" {
		t.Fatalf("add sdlc: installed=%q removed=%q sets=%v", changes(resp.GetInstalled()), changes(resp.GetRemoved()), resp.GetSkillSets())
	}

	// Skills the owner installed by hand, one of them under a set's namespace
	// prefix, are never the installer's to remove.
	writeSkill(t, home, "my-own", "mine\n")
	writeSkill(t, home, "qa-handmade", "mine too\n")

	// Narrowing to sdlc removes exactly qa's skill.
	resp, err = apply(t, s, "sdlc")
	if err != nil {
		t.Fatal(err)
	}
	if changes(resp.GetRemoved()) != "qa:qa-unit-test" || len(resp.GetInstalled()) != 0 || resp.GetUnchanged() || strings.Join(resp.GetSkillSets(), ",") != "sdlc" {
		t.Fatalf("remove qa: installed=%q removed=%q unchanged=%v", changes(resp.GetInstalled()), changes(resp.GetRemoved()), resp.GetUnchanged())
	}
	if got := skillDirs(t, home); strings.Join(got, ",") != "_shared,architect-design,engineer-implement,my-own,qa-handmade" {
		t.Fatalf("dirs after removing qa = %v", got)
	}
	if m := readSkillSetManifest(t, home); !reflect.DeepEqual(m, map[string][]string{"sdlc": {"architect-design", "engineer-implement"}}) {
		t.Fatalf("manifest = %v", m)
	}

	// The empty list removes every recorded set; the hand-installed skills stay.
	resp, err = apply(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if changes(resp.GetRemoved()) != "sdlc:architect-design,engineer-implement" || resp.GetUnchanged() || len(resp.GetSkillSets()) != 0 {
		t.Fatalf("remove all: %v", resp)
	}
	if got := skillDirs(t, home); strings.Join(got, ",") != "my-own,qa-handmade" {
		t.Fatalf("dirs after removing all = %v", got)
	}
	if m := readSkillSetManifest(t, home); len(m) != 0 {
		t.Fatalf("manifest = %v", m)
	}
	if *installs != 5 {
		t.Errorf("installer ran %d times, want once per call", *installs)
	}
}

// Writing the skills where `code install` writes them must create the files
// as the installer does: the manifest is beside the skills, and the skill
// files themselves are the bundle's.
func TestApplyBoxSkillSets_InstallsTheBundleFiles(t *testing.T) {
	home := t.TempDir()
	s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	if _, err := apply(t, s, "security"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "skills", "security-triage", "SKILL.md"))
	if err != nil || string(data) != "# security-triage/SKILL.md\n" {
		t.Fatalf("SKILL.md = %q, %v", data, err)
	}
	if !exists(filepath.Join(home, ".claude", "skills", "_shared", "tracker.md")) {
		t.Error("_shared was not installed")
	}
}

// Q3 decision (#3503): a set installed before the manifest existed (by
// `code install` or the recipe) can be added — kept in the list, it is
// re-installed and recorded — but omitting it is a typed refusal, because
// what it installed was never recorded.
func TestApplyBoxSkillSets_SetPredatingTheManifest(t *testing.T) {
	home := t.TempDir()
	s, _, installs := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	// A pre-manifest install: the installer alone, as `code install` runs it.
	if _, err := s.boxSkillSetsInstall("alice-container", "alice", "v9.9.9", sdlcskills.SkillSetsFromIDs([]string{"qa", "sdlc"})); err != nil {
		t.Fatal(err)
	}
	*installs = 0
	if exists(filepath.Join(home, ".claude", "skills", boxSkillSetsManifestFile)) {
		t.Fatal("fixture: the installer must not write the per-set manifest")
	}

	_, err := apply(t, s, "sdlc")
	reason, subject := skillSetRefusalOf(t, err)
	if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_SET_PREDATES_MANIFEST || subject != "qa" {
		t.Fatalf("omit a pre-manifest set: %v (reason %v, subject %q)", err, reason, subject)
	}
	if *installs != 0 || !exists(filepath.Join(home, ".claude", "skills", "qa-unit-test")) {
		t.Fatalf("a refusal must change nothing: installs=%d", *installs)
	}

	resp, err := apply(t, s, "sdlc", "qa")
	if err != nil {
		t.Fatal(err)
	}
	if changes(resp.GetInstalled()) != "qa:qa-unit-test sdlc:architect-design,engineer-implement" || resp.GetUnchanged() {
		t.Fatalf("adopt: installed=%q unchanged=%v", changes(resp.GetInstalled()), resp.GetUnchanged())
	}
	if m := readSkillSetManifest(t, home); !reflect.DeepEqual(m, map[string][]string{"qa": {"qa-unit-test"}, "sdlc": {"architect-design", "engineer-implement"}}) {
		t.Fatalf("manifest = %v", m)
	}

	// Recorded now, so it can be removed.
	resp, err = apply(t, s, "sdlc")
	if err != nil {
		t.Fatal(err)
	}
	if changes(resp.GetRemoved()) != "qa:qa-unit-test" || exists(filepath.Join(home, ".claude", "skills", "qa-unit-test")) {
		t.Fatalf("remove after adopting: %v", resp)
	}
}

// Acceptance: a box with a run in progress is refused with a typed reason and
// nothing is changed. A run in progress is a code run that is RUNNING (an
// exited one is not), or a skill run executing in this box.
func TestApplyBoxSkillSets_RefusesUnderARun(t *testing.T) {
	boot := hostBootID(t)
	t.Run("a RUNNING code run", func(t *testing.T) {
		home := t.TempDir()
		s, logDir, installs := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
		writeRecord(t, logDir, recordSpec{name: "code", pid: os.Getpid(), boot: boot, started: time.Now().Add(-time.Minute)})
		_, err := apply(t, s, "qa")
		reason, subject := skillSetRefusalOf(t, err)
		if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS || subject != "alice-container" {
			t.Fatalf("err = %v (reason %v, subject %q)", err, reason, subject)
		}
		if !strings.Contains(status.Convert(err).Message(), `"code"`) {
			t.Errorf("message %q does not name the run", status.Convert(err).Message())
		}
		if *installs != 0 || exists(filepath.Join(home, ".claude", "skills")) {
			t.Error("a refusal must change nothing")
		}
	})
	t.Run("an exited code run is not in progress", func(t *testing.T) {
		home := t.TempDir()
		s, logDir, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
		writeRecord(t, logDir, recordSpec{name: "code", pid: os.Getpid(), boot: boot, started: time.Now().Add(-time.Hour), exitCode: exitWith(0)})
		if _, err := apply(t, s, "qa"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a skill run in this box", func(t *testing.T) {
		home := t.TempDir()
		s, _, installs := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
		s.runRegistry = runlease.NewRegistry()
		s.runRegistry.Register("run-elsewhere", runlease.Info{SkillID: "x", Box: "agent-x-container"})
		if _, err := apply(t, s, "qa"); err != nil {
			t.Fatalf("a skill run in another box must not refuse: %v", err)
		}
		s.runRegistry.Register("run-here", runlease.Info{SkillID: "x", Box: "alice-container"})
		_, err := apply(t, s, "security")
		reason, _ := skillSetRefusalOf(t, err)
		if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS || !strings.Contains(status.Convert(err).Message(), "run-here") {
			t.Fatalf("err = %v", err)
		}
		if *installs != 1 {
			t.Errorf("installer ran %d times, want 1 (the refused call ran nothing)", *installs)
		}
	})
}

// The box must exist and be running; a manifest the daemon cannot read is a
// refusal that changes nothing (never a removal based on a guess); the
// release defaults to the daemon's own.
func TestApplyBoxSkillSets_BoxStateAndRelease(t *testing.T) {
	t.Run("stopped box", func(t *testing.T) {
		s, _, installs := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_STOPPED)
		if _, err := apply(t, s, "qa"); status.Code(err) != codes.FailedPrecondition || *installs != 0 {
			t.Fatalf("err = %v, installs = %d", err, *installs)
		}
	})
	t.Run("no such box", func(t *testing.T) {
		s, _, _ := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
		s.runCheckoutBoxes = func(context.Context) ([]box.BoxStatus, error) { return nil, nil }
		if _, err := apply(t, s, "qa"); status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("corrupt manifest", func(t *testing.T) {
		home := t.TempDir()
		s, _, installs := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
		if err := os.MkdirAll(filepath.Join(home, ".claude", "skills"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(home, ".claude", "skills", boxSkillSetsManifestFile), "{not json")
		if _, err := apply(t, s, "qa"); status.Code(err) != codes.FailedPrecondition || *installs != 0 {
			t.Fatalf("err = %v, installs = %d", err, *installs)
		}
	})
	t.Run("release defaults to the daemon's", func(t *testing.T) {
		home := t.TempDir()
		s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
		var gotRelease string
		inner := s.boxSkillSetsInstall
		s.boxSkillSetsInstall = func(box, user, release string, sets sdlcskills.SkillSets) (string, error) {
			gotRelease = release
			return inner(box, user, release, sets)
		}
		resp, err := s.ApplyBoxSkillSets(tenantCtx("alice"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"qa"}})
		if err != nil {
			t.Fatal(err)
		}
		if want := agentRuntimeReleaseTag(); gotRelease != want || resp.GetRelease() != want || !strings.HasPrefix(want, "v") {
			t.Errorf("release passed %q, reported %q, want %q", gotRelease, resp.GetRelease(), want)
		}
	})
}

// Production wires the install to the box user's exec with the shared
// installer script, at the requested release, for the repository the
// installer defaults to.
func TestBoxSkillSetsInstallFn_RunsTheSharedInstallerAsTheUser(t *testing.T) {
	var gotBox, gotUser, gotScript string
	s := &ContainerServer{boxRunStartExec: func(box, user, script string) (string, error) {
		gotBox, gotUser, gotScript = box, user, script
		return "", nil
	}}
	if _, err := s.boxSkillSetsInstallFn()("alice-container", "alice", "v1.2.3", sdlcskills.SkillSetsFromIDs([]string{"qa", "sdlc"})); err != nil {
		t.Fatal(err)
	}
	if gotBox != "alice-container" || gotUser != "alice" || gotScript != sdlcskills.InstallScript(sdlcskills.DefaultRepo, "v1.2.3", sdlcskills.SkillSetsFromIDs([]string{"qa", "sdlc"})) {
		t.Errorf("install = %q %q\n%s", gotBox, gotUser, gotScript)
	}
	if !strings.Contains(gotScript, `SKILL_SETS="qa,sdlc"`) || !strings.Contains(gotScript, `RELEASE="v1.2.3"`) || strings.Contains(gotScript, "sudo") {
		t.Errorf("script:\n%s", gotScript)
	}
	if (&ContainerServer{}).boxSkillSetsInstallFn() != nil {
		t.Error("no exec seam and no manager must give no installer")
	}
}

// What the box reports about itself is untrusted: a manifest entry or an
// installer-manifest line outside the installer's own name charset is dropped,
// and a set id outside the lock's charset makes the manifest unreadable.
func TestParseBoxSkillSetsState(t *testing.T) {
	out := "=== sets\n" + `{"version":1,"release":"v1","sets":{"qa":["qa-unit-test","../etc","ok_dir"]}}` + "\n=== installer\nqa-unit-test\n../etc\n$(x)\n_shared\n\n=== end\n"
	st, err := parseBoxSkillSetsState(out)
	if err != nil {
		t.Fatal(err)
	}
	if !st.hasManifest || !reflect.DeepEqual(st.manifest.Sets, map[string][]string{"qa": {"ok_dir", "qa-unit-test"}}) {
		t.Errorf("manifest = %+v", st.manifest)
	}
	if !reflect.DeepEqual(st.installerDirs, []string{"_shared", "qa-unit-test"}) {
		t.Errorf("installer dirs = %v", st.installerDirs)
	}
	empty, err := parseBoxSkillSetsState("=== sets\n\n=== installer\n\n=== end\n")
	if err != nil || empty.hasManifest || len(empty.manifest.Sets) != 0 || len(empty.installerDirs) != 0 {
		t.Errorf("empty box: %+v, %v", empty, err)
	}
	for _, bad := range []string{
		"=== sets\n{nope\n=== installer\n\n=== end\n",
		"=== sets\n" + `{"version":1,"sets":{"Q A":["x"]}}` + "\n=== installer\n\n=== end\n",
		"garbage without markers",
	} {
		if _, err := parseBoxSkillSetsState(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// Skills are attributed to the target set whose namespace prefixes them; a
// longer namespace wins over a shorter one it extends, _shared belongs to no
// set, and an installer-owned directory no target set claims is reported
// without a set rather than silently.
func TestAttributeSkillDirs(t *testing.T) {
	known := map[string][]string{"sdlc": {"qa-ext", "writer"}, "qa": {"qa"}}
	bySet, loose := attributeSkillDirs([]string{"_shared", "qa-unit-test", "qa-ext-review", "writer-docs", "old-thing"}, []string{"qa", "sdlc"}, known)
	if !reflect.DeepEqual(bySet, map[string][]string{"qa": {"qa-unit-test"}, "sdlc": {"qa-ext-review", "writer-docs"}}) {
		t.Errorf("bySet = %v", bySet)
	}
	if !reflect.DeepEqual(loose, []string{"old-thing"}) {
		t.Errorf("loose = %v", loose)
	}
}

// The embedded lock defines the sets the RPC accepts; the three shipped today
// must stay accepted, so a control plane can rely on their ids.
func TestApplyBoxSkillSets_EmbeddedLockSets(t *testing.T) {
	known, err := knownSkillSets()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sdlc", "qa", "security"} {
		if _, ok := known[id]; !ok {
			t.Errorf("embedded lock has no set %q", id)
		}
	}
}
