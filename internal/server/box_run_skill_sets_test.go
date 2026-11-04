//go:build !containarium_client

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/gateway"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
// stranger is PermissionDenied, an unknown set id is the typed refusal, all
// before the box is touched. The install itself lands in a later slice, so a
// well-formed call is Unimplemented for now, and nothing was executed in the
// box on any of these paths.
func TestApplyBoxSkillSets_ContractGates(t *testing.T) {
	b := &shBox{}
	s, _ := boxRunServer(t, b)
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
	if _, err := s.ApplyBoxSkillSets(tenantCtx("bob"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"qa"}}); status.Code(err) != codes.Unimplemented {
		t.Errorf("collaborator, well-formed: %v, want Unimplemented until the server slice lands", err)
	}
	if len(b.boxes) != 0 {
		t.Errorf("the contract gates executed %d script(s) in the box", len(b.boxes))
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
