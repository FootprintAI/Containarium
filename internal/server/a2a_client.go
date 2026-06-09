package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// a2aPort is the TCP port a skill's in-box A2A server listens on. The daemon
// reaches a running peer at http://<container-ip>:<a2aPort>. Serving this
// endpoint is the agent-runtime image's job (Phase 1 integration seam); the
// daemon side (resolve + send) is implemented here.
const a2aPort = 8674

// a2aTasksPath is the in-box A2A endpoint that accepts a task and returns an
// artifact. Body in = AgentTask (protojson); body out = AgentArtifact.
const a2aTasksPath = "/tasks"

// sendA2ATask delivers a task to a peer agent's in-box A2A server and returns
// its artifact. baseURL is http://<ip>:<a2aPort>. The HTTP timeout is carried
// by ctx (the caller sets it). This is the realization of the AgentTask /
// AgentArtifact proto contract on the wire.
func sendA2ATask(ctx context.Context, baseURL string, task *pb.AgentTask) (*pb.AgentArtifact, error) {
	body, err := protojson.Marshal(task)
	if err != nil {
		return nil, fmt.Errorf("marshal task: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+a2aTasksPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build a2a request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("a2a request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("a2a peer returned %d: %s", resp.StatusCode, string(respBody))
	}
	art := &pb.AgentArtifact{}
	if err := protojson.Unmarshal(respBody, art); err != nil {
		return nil, fmt.Errorf("decode artifact: %w", err)
	}
	return art, nil
}
