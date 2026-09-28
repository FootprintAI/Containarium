package server

import (
	"bytes"
	"context"
	"errors"
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

// a2aSecretPurpose domain-separates the per-box A2A credential from every other
// secret derived from the daemon's signing key. Versioned: bumping it rotates
// every box's credential on its next provision.
const a2aSecretPurpose = "containarium/a2a-box/v1"

// errA2AUnauthorized is what a peer refusing the daemon's credential returns.
// Distinguished from an unreachable peer because it means something different:
// the box is up and serving, but it was seeded by a different daemon (or before
// this daemon's JWT signing key was rotated), so it does not recognize us.
// Reprovisioning the box reseeds its credential.
var errA2AUnauthorized = errors.New("peer refused the daemon's A2A credential")

// agentA2ASecret returns the per-box A2A credential for one skill's box: the
// secret the daemon seeded into that box's serve-mode process and must present
// on every POST /tasks (#2125, decision D1 in
// docs/architecture/execution-scoped-authorization.md).
//
// Derived, not stored: the daemon recomputes it whenever it needs it, so a
// daemon restart does not strand a running box, and no box can compute another
// box's. Empty when the daemon has no token manager (tests) or the skill is
// unnamed — callers treat that as "cannot authenticate" and refuse to send.
func (s *AgentSkillServer) agentA2ASecret(skillID string) string {
	if s == nil || s.tokens == nil {
		return ""
	}
	return s.tokens.DeriveSharedSecret(a2aSecretPurpose, skillID)
}

// sendA2ATask delivers a task to a peer agent's in-box A2A server and returns
// its artifact. baseURL is http://<ip>:<a2aPort>. The HTTP timeout is carried
// by ctx (the caller sets it). This is the realization of the AgentTask /
// AgentArtifact proto contract on the wire.
//
// bearer is the peer box's own A2A credential (agentA2ASecret). It is required:
// POST /tasks is a daemon-only endpoint, so a request the peer is bound to
// refuse is not worth making — sending it anyway would only move the failure
// later and put a task body on the wire for nothing. The credential travels as
// an Authorization header rather than as an AgentTask field, because it belongs
// to the transport and must not end up inside a task the peer journals.
func sendA2ATask(ctx context.Context, baseURL string, task *pb.AgentTask, bearer string) (*pb.AgentArtifact, error) {
	if bearer == "" {
		return nil, fmt.Errorf("%w: the daemon holds no credential for this peer", errA2AUnauthorized)
	}
	body, err := protojson.Marshal(task)
	if err != nil {
		return nil, fmt.Errorf("marshal task: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+a2aTasksPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build a2a request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("a2a request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w (%d): %s", errA2AUnauthorized, resp.StatusCode, string(respBody))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("a2a peer returned %d: %s", resp.StatusCode, string(respBody))
	}
	art := &pb.AgentArtifact{}
	if err := protojson.Unmarshal(respBody, art); err != nil {
		return nil, fmt.Errorf("decode artifact: %w", err)
	}
	return art, nil
}
