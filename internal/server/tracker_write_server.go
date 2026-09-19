package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// trackerWriterFor resolves provider to its WriterProvider — the same
// resolution and test-override mechanism trackerProviderFor uses (both
// real adapters, and any fake a test registers via SetTrackerDescribers,
// satisfy WriterProvider; the map is declared as ReaderProvider only
// because #1921's read-only callers never needed more).
func (s *ContainerServer) trackerWriterFor(provider pb.TrackerProvider) (tracker.WriterProvider, error) {
	rp, err := s.trackerProviderFor(provider)
	if err != nil {
		return nil, err
	}
	wp, ok := rp.(tracker.WriterProvider)
	if !ok {
		return nil, fmt.Errorf("provider %v does not support write verbs", provider)
	}
	return wp, nil
}

// resolveWriterConn is resolveReaderConn's write-verb counterpart:
// resolves a named connection to its WriterProvider adapter and a
// ready-to-use tracker.Conn. Tenant scoping and the tracker:write scope
// are the caller's responsibility; the run <-> connection JWT-claim
// cross-check (#1922 step 6) is not enforced here yet, same as the read
// verbs.
func (s *ContainerServer) resolveWriterConn(ctx context.Context, username, connectionName string) (tracker.WriterProvider, tracker.Conn, error) {
	trackerConn, err := s.trackerStore.Get(ctx, username, connectionName)
	if err != nil {
		return nil, tracker.Conn{}, mapTrackerError(err)
	}
	provider, err := s.trackerWriterFor(trackerConn.Provider)
	if err != nil {
		return nil, tracker.Conn{}, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if s.secretsStore == nil {
		return nil, tracker.Conn{}, status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	cred, err := s.secretsStore.BrokerCredential(ctx, username, trackerConn.CredentialSecret)
	if err != nil {
		return nil, tracker.Conn{}, status.Errorf(codes.FailedPrecondition, "resolve broker credential: %v", err)
	}
	return provider, tracker.Conn{
		BaseURL:    trackerConn.BaseURL,
		Project:    trackerConn.Project,
		Credential: cred,
	}, nil
}

// identityFromContext resolves the platform identity to stamp on a
// brokered write, built only from the verified token's claims and (for
// a run-scoped token) the run registry — never from a request field,
// per the design note's anti-forgery invariant for the identity stamp.
//
// A run-scoped token names its run via the run_id claim (#1922); its
// skill and model are resolved from the shared run registry, which
// AgentSkillServer populates at RunAgentSkill and clears at lease end.
// An unknown run id (e.g. the registry was restarted since the run
// began) still stamps the run id itself, just with an empty skill/model
// — best-effort, never a reason to fail the write.
//
// An operator/human token carries no run_id claim at all. The design
// note frames every brokered write as something an agent run does, but
// the CLI's own tracker issue comment/claim/label commands are meant to
// work from a human's own token too. Stamped as "operator/<username>"
// instead: still exactly what the caller authenticated as.
func (s *ContainerServer) identityFromContext(ctx context.Context) tracker.Identity {
	runID, hasRun := auth.RunIDFromGRPCContext(ctx)
	if !hasRun || runID == "" {
		username, _, _ := auth.SubjectFromGRPCContext(ctx)
		return tracker.Identity{RunID: username, SkillID: "operator"}
	}
	var info runlease.Info
	if s.runRegistry != nil {
		info, _ = s.runRegistry.Get(runID)
	}
	return tracker.Identity{RunID: runID, SkillID: info.SkillID, Model: info.Model}
}

// CommentOnTrackerIssue posts a stamped, sanitized comment on an issue
// or change request.
func (s *ContainerServer) CommentOnTrackerIssue(ctx context.Context, req *pb.CommentOnTrackerIssueRequest) (*pb.CommentOnTrackerIssueResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerWrite); err != nil {
		return nil, err
	}
	if s.trackerStore == nil {
		return nil, status.Error(codes.Unavailable, "tracker store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
	if req.Body == "" {
		return nil, status.Error(codes.InvalidArgument, "body is required")
	}

	provider, conn, err := s.resolveWriterConn(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, err
	}

	id := s.identityFromContext(ctx)
	body := tracker.Sanitize(req.Body) + "\n\n" + tracker.Stamp(id, tracker.KindComment)
	comment, err := provider.Comment(ctx, conn, req.Number, body)
	if err != nil {
		return nil, mapProviderError(err)
	}

	s.auditTrackerWrite(ctx, "tracker.comment", req.Username, req.Connection, req.Number, trackerCommentAuditDetail{
		Connection: req.Connection,
		Number:     req.Number,
		RunID:      id.RunID,
		SkillID:    id.SkillID,
	})
	return &pb.CommentOnTrackerIssueResponse{Comment: toProtoComment(comment)}, nil
}

// ---- tracker write audit rows (#1922) --------------------------------
//
// One row per write, ResourceType "tracker_issue", Detail marshalled from
// the named structs below rather than a map — same idiom as
// agent_server.go's run-lease audit rows.

type trackerCommentAuditDetail struct {
	Connection string `json:"connection"`
	Number     int64  `json:"number"`
	RunID      string `json:"run_id"`
	SkillID    string `json:"skill_id,omitempty"`
}

// auditTrackerWrite records a tracker write verb's outcome. Best-effort
// — audit must never fail the call. No-op until the audit store is
// wired. detail is one of the named structs above.
func (s *ContainerServer) auditTrackerWrite(ctx context.Context, action, username, connection string, number int64, detail any) {
	if s.auditStore == nil {
		return
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		log.Printf("[tracker] marshal audit detail for %s: %v", action, err)
		return
	}
	if err := s.auditStore.Log(ctx, &audit.AuditEntry{
		Username:     username,
		Action:       action,
		ResourceType: "tracker_issue",
		ResourceID:   fmt.Sprintf("%s/%s#%d", username, connection, number),
		Detail:       string(payload),
	}); err != nil {
		log.Printf("[tracker] audit %s %s/%s#%d: %v", action, username, connection, number, err)
	}
}
