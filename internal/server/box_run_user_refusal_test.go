package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// violationTypeOf returns the type of the single PreconditionFailure violation on
// err, or "" if it carries none.
func violationTypeOf(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return ""
	}
	for _, d := range st.Details() {
		if p, ok := d.(*errdetails.PreconditionFailure); ok && len(p.GetViolations()) == 1 {
			return p.GetViolations()[0].GetType()
		}
	}
	return ""
}

// A refusal for want of a run-user sign-in carries a TYPED reason, so the hosted
// control plane can tell the box's owner to sign in again without matching on
// message text. "Never signed in" and "expired" are different reasons.
func TestBoxRunSignInRefusal_CarriesATypedViolation(t *testing.T) {
	for state, want := range map[engine.CredentialStatusSource]string{
		engine.CredentialStatusNone:    BoxRunViolationRunUserNotSignedIn,
		engine.CredentialStatusExpired: BoxRunViolationRunUserSignInExpired,
	} {
		t.Run(string(state), func(t *testing.T) {
			err := boxRunSignInRefusal("alice-container", state, "/srv/ctn-run")
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.FailedPrecondition {
				t.Fatalf("err = %v, want a FailedPrecondition status", err)
			}
			var pf *errdetails.PreconditionFailure
			for _, d := range st.Details() {
				if p, ok := d.(*errdetails.PreconditionFailure); ok {
					pf = p
				}
			}
			if pf == nil || len(pf.GetViolations()) != 1 {
				t.Fatalf("details = %v, want one PreconditionFailure violation", st.Details())
			}
			v := pf.GetViolations()[0]
			if v.GetType() != want || v.GetSubject() != "alice-container" {
				t.Errorf("violation = {%s %s}, want {%s alice-container}", v.GetType(), v.GetSubject(), want)
			}
			if !strings.Contains(v.GetDescription(), "claude auth login") || !strings.Contains(st.Message(), "claude auth login") {
				t.Errorf("the human message must carry the sign-in command: %q", st.Message())
			}
		})
	}
	if BoxRunViolationRunUserNotSignedIn == BoxRunViolationRunUserSignInExpired {
		t.Error("the two reasons must differ")
	}
}

// The typed reason survives the REST gateway's own error encoding, which is the
// form the hosted control plane receives.
func TestBoxRunSignInRefusal_SurvivesTheRESTGateway(t *testing.T) {
	err := boxRunSignInRefusal("alice-container", engine.CredentialStatusExpired, "/srv/ctn-run")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/containers/alice/code-runs", nil)
	runtime.DefaultHTTPErrorHandler(context.Background(), runtime.NewServeMux(), &runtime.JSONPb{}, w, req, err)

	var body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Type       string `json:"@type"`
			Violations []struct {
				Type    string `json:"type"`
				Subject string `json:"subject"`
			} `json:"violations"`
		} `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("gateway body is not JSON: %v\n%s", err, w.Body.String())
	}
	if body.Code != int(codes.FailedPrecondition) || !strings.Contains(body.Message, "claude auth login") {
		t.Errorf("code=%d message=%q", body.Code, body.Message)
	}
	if len(body.Details) != 1 || !strings.HasSuffix(body.Details[0].Type, "google.rpc.PreconditionFailure") ||
		len(body.Details[0].Violations) != 1 || body.Details[0].Violations[0].Type != BoxRunViolationRunUserSignInExpired {
		t.Fatalf("typed reason lost in the REST body:\n%s", w.Body.String())
	}
}
