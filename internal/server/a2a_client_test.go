package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestSendA2ATask exercises the A2A client against a stub peer that speaks the
// AgentTask -> AgentArtifact contract (what the in-box A2A server will do).
func TestSendA2ATask(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != a2aTasksPath {
			t.Errorf("unexpected path %q, want %q", r.URL.Path, a2aTasksPath)
		}
		body, _ := io.ReadAll(r.Body)
		task := &pb.AgentTask{}
		if err := protojson.Unmarshal(body, task); err != nil {
			t.Errorf("peer could not decode task: %v", err)
		}
		art := &pb.AgentArtifact{
			TaskId:     task.Id,
			OutputJson: `{"ok":true}`,
			State:      pb.AgentTaskState_AGENT_TASK_STATE_COMPLETED,
		}
		out, _ := protojson.Marshal(art)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	art, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "task-1", InputJson: `{"q":"hi"}`})
	if err != nil {
		t.Fatalf("sendA2ATask: %v", err)
	}
	if art.TaskId != "task-1" {
		t.Errorf("task_id = %q, want task-1", art.TaskId)
	}
	if art.State != pb.AgentTaskState_AGENT_TASK_STATE_COMPLETED {
		t.Errorf("state = %v, want COMPLETED", art.State)
	}
	if art.OutputJson != `{"ok":true}` {
		t.Errorf("output = %q", art.OutputJson)
	}
}

// TestSendA2ATaskPeerError surfaces a non-2xx peer response as an error.
func TestSendA2ATaskPeerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "t"})
	if err == nil {
		t.Fatal("expected error for 502 peer response, got nil")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should mention status, got: %v", err)
	}
}
