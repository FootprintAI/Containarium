package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func serveError(t *testing.T, err error) (int, map[string]json.RawMessage) {
	t.Helper()
	w := httptest.NewRecorder()
	ErrorHandler(context.Background(), runtime.NewServeMux(), &runtime.JSONPb{}, w, httptest.NewRequest(http.MethodPost, "/v1/x", nil), err)
	var body map[string]json.RawMessage
	if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
		t.Fatalf("body is not JSON: %v\n%s", e, w.Body.String())
	}
	return w.Code, body
}

// Typed status details reach the REST caller (#3277), in grpc-gateway's own
// shape, alongside the error and code fields existing readers use.
func TestErrorHandler_KeepsStatusDetails(t *testing.T) {
	st, err := status.New(codes.FailedPrecondition, "sign in first").WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{Type: "RUN_USER_NOT_SIGNED_IN", Subject: "alice-container", Description: "sign in first"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpCode, body := serveError(t, st.Err())
	if httpCode != http.StatusBadRequest {
		t.Fatalf("http status = %d", httpCode)
	}
	var code int
	var msg, errStr string
	_ = json.Unmarshal(body["code"], &code)
	_ = json.Unmarshal(body["message"], &msg)
	_ = json.Unmarshal(body["error"], &errStr)
	if code != http.StatusBadRequest || msg != "sign in first" || errStr == "" {
		t.Errorf("code=%d message=%q error=%q", code, msg, errStr)
	}
	var details []struct {
		Type       string `json:"@type"`
		Violations []struct {
			Type    string `json:"type"`
			Subject string `json:"subject"`
		} `json:"violations"`
	}
	if e := json.Unmarshal(body["details"], &details); e != nil || len(details) != 1 {
		t.Fatalf("details = %s (%v)", body["details"], e)
	}
	d := details[0]
	if d.Type != "type.googleapis.com/google.rpc.PreconditionFailure" || len(d.Violations) != 1 ||
		d.Violations[0].Type != "RUN_USER_NOT_SIGNED_IN" || d.Violations[0].Subject != "alice-container" {
		t.Errorf("detail = %+v", d)
	}
}

// An error with no details keeps today's body: no details key.
func TestErrorHandler_NoDetailsNoKey(t *testing.T) {
	_, body := serveError(t, status.Error(codes.NotFound, "gone"))
	if _, ok := body["details"]; ok {
		t.Errorf("details present: %s", body["details"])
	}
	if _, ok := body["error"]; !ok {
		t.Error("error field missing")
	}
}

// A non-status error still gets a body, with no message or details.
func TestErrorHandler_PlainError(t *testing.T) {
	code, body := serveError(t, context.DeadlineExceeded)
	if code == 0 || len(body["error"]) == 0 {
		t.Fatalf("code=%d body=%v", code, body)
	}
}
