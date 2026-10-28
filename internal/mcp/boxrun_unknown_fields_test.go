package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A newer daemon may add response fields; an older MCP client must still
// decode the response (#3190).
func TestBoxRunResponsesDiscardUnknownFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"futureField":"x"}`))
			return
		}
		_, _ = w.Write([]byte(`{"futureField":"x","runs":[{"futureNested":1}],"inputs":[{"futureNested":1}]}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")

	t.Run("ListBoxRuns", func(t *testing.T) {
		runs, err := c.ListBoxRuns("alice")
		if err != nil {
			t.Fatalf("ListBoxRuns: %v", err)
		}
		if len(runs) != 1 {
			t.Errorf("got %d runs, want 1", len(runs))
		}
	})
	t.Run("TailBoxRunLog", func(t *testing.T) {
		if _, err := c.TailBoxRunLog(&pb.TailBoxRunLogRequest{Username: "alice", RunName: "r1"}); err != nil {
			t.Fatalf("TailBoxRunLog: %v", err)
		}
	})
	t.Run("ListRunInputs", func(t *testing.T) {
		if _, err := c.ListRunInputs(&pb.ListRunInputsRequest{Username: "alice", RunName: "r1"}); err != nil {
			t.Fatalf("ListRunInputs: %v", err)
		}
	})
	t.Run("AnswerRunInput", func(t *testing.T) {
		if _, err := c.AnswerRunInput(&pb.AnswerRunInputRequest{Username: "alice", RunName: "r1", RequestId: "q1"}); err != nil {
			t.Fatalf("AnswerRunInput: %v", err)
		}
	})
}
