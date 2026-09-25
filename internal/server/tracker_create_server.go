package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateTrackerIssue files a follow-up issue on the connection's
// tracker (#2024; design docs/architecture/issue-triggered-agents.md,
// "CreateTrackerIssue verb" and "Chain guards"). Order of checks is the
// contract, not an implementation detail:
//
//  1. scope / tenant / binding — before touching the store;
//  2. the connection's label allow-list — BEFORE any upstream call, so
//     an injected "add deploy:prod" never creates anything;
//  3. run-scoped tokens must name a parent (lineage), get
//     agent:needs-approval forced on unless the policy opted into
//     auto_chain, and are bounded by max_depth / max_children_per_run —
//     both counted in the same transaction as the lineage insert, with
//     the upstream create happening inside that transaction so a cap
//     can never be raced past;
//  4. the body sent upstream is the sanitized agent text plus a parent
//     link and an identity stamp built only from the verified token;
//  5. one back-link comment on the parent; one audit row.
//
// An operator/human token (no run_id claim) files a root or child issue
// with no lineage row — a human-created issue is depth 0 by definition
// — and no forced gate label.
func (s *ContainerServer) CreateTrackerIssue(ctx context.Context, req *pb.CreateTrackerIssueRequest) (*pb.CreateTrackerIssueResponse, error) {
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
	title := sanitizeIssueTitle(req.Title)
	if title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}
	if req.ParentNumber < 0 {
		return nil, status.Error(codes.InvalidArgument, "parent_number must not be negative")
	}

	runID, isRun := auth.RunIDFromGRPCContext(ctx)
	isRun = isRun && runID != ""
	if isRun && req.ParentNumber == 0 {
		return nil, status.Error(codes.InvalidArgument, "parent_number is required for a run-scoped token: every agent-filed follow-up must link its parent")
	}

	if err := enforceConnectionBinding(ctx, req.Connection); err != nil {
		return nil, err
	}
	record, err := s.trackerStore.Get(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, mapTrackerError(err)
	}
	policy := tracker.PolicyFromProto(record.Policy)

	// Allow-list, before any upstream call (and before resolving the
	// credential — nothing about the tracker is touched on rejection).
	labels := dedupeLabels(req.Labels)
	if err := policy.CheckLabels(labels, isRun); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if isRun && !policy.AutoChain {
		labels = appendUniqueLabel(labels, tracker.LabelNeedsApproval)
	}

	provider, conn, err := s.writerConnFor(ctx, record)
	if err != nil {
		return nil, err
	}

	id := s.identityFromContext(ctx)
	newIssue := tracker.NewIssue{
		Title:  title,
		Body:   composeIssueBody(req.Body, req.ParentNumber, id),
		Labels: labels,
	}

	var created tracker.Issue
	var depth int32
	lineageRecorded := false
	if isRun {
		var upstreamErr error
		rec, err := s.trackerStore.RecordChild(ctx, tracker.Lineage{
			Username: req.Username, Connection: req.Connection,
			ParentNumber: req.ParentNumber, CreatedByRun: runID,
		}, policy.MaxDepth, policy.MaxChildrenPerRun, func(ctx context.Context) (int64, error) {
			issue, cerr := provider.CreateIssue(ctx, conn, newIssue)
			if cerr != nil {
				upstreamErr = cerr
				return 0, cerr
			}
			created = issue
			return issue.Number, nil
		})
		var recErr *tracker.LineageRecordError
		switch {
		case err == nil:
			depth = rec.Depth
			lineageRecorded = true
		case errors.As(err, &recErr):
			// The issue exists upstream; only its lineage row is missing.
			// Report it as created (and audit it below with
			// lineage_recorded=false) — an error here would make the
			// caller retry and file a duplicate (review of #2034).
			depth = recErr.Depth
			log.Printf("[tracker] %s/%s: %v", req.Username, req.Connection, recErr)
		case errors.Is(err, tracker.ErrDepthExceeded):
			return nil, status.Errorf(codes.FailedPrecondition, "follow-up would exceed the connection's max_depth (%d): %v", policy.MaxDepth, err)
		case errors.Is(err, tracker.ErrFanoutExceeded):
			return nil, status.Errorf(codes.ResourceExhausted, "this run has reached the connection's max_children_per_run (%d): %v", policy.MaxChildrenPerRun, err)
		case upstreamErr != nil:
			return nil, mapProviderError(upstreamErr)
		default:
			return nil, status.Errorf(codes.Internal, "record issue lineage: %v", err)
		}
	} else {
		// Same rule as RecordChild's create: once committed-to, the
		// upstream create must not be abandoned because the caller went
		// away mid-request (the issue would exist upstream, unaudited).
		createCtx, cancelCreate := context.WithTimeout(context.WithoutCancel(ctx), tracker.UpstreamCreateTimeout)
		created, err = provider.CreateIssue(createCtx, conn, newIssue)
		cancelCreate()
		if err != nil {
			return nil, mapProviderError(err)
		}
	}

	// The child exists upstream from here on. The back-link and the audit
	// row must not depend on the caller still being connected (review of
	// #2034): detach from cancellation, bounded by a short timeout.
	postCtx, cancelPost := context.WithTimeout(context.WithoutCancel(ctx), postCreateTimeout)
	defer cancelPost()

	// One back-link comment on the parent. Best-effort once the child
	// exists: failing the RPC here would make the caller retry and file
	// a duplicate child, which is worse than a missing back-link — the
	// audit row records whether it landed.
	parentCommentPosted := false
	if req.ParentNumber > 0 {
		backlink := fmt.Sprintf("Filed follow-up #%d: %s", created.Number, title) + "\n\n" + tracker.Stamp(id, tracker.KindComment)
		if _, cerr := provider.Comment(postCtx, conn, req.ParentNumber, backlink); cerr != nil {
			log.Printf("[tracker] %s/%s: back-link comment on #%d for child #%d: %v", req.Username, req.Connection, req.ParentNumber, created.Number, cerr)
		} else {
			parentCommentPosted = true
		}
	}

	s.auditTrackerWrite(postCtx, "tracker.issue_created", req.Username, req.Connection, created.Number, trackerIssueCreatedAuditDetail{
		LineageRecorded:     lineageRecorded,
		Connection:          req.Connection,
		Project:             record.Project,
		Number:              created.Number,
		ParentNumber:        req.ParentNumber,
		Depth:               depth,
		RunID:               id.RunID,
		SkillID:             id.SkillID,
		Model:               id.Model,
		Labels:              labels,
		ParentCommentPosted: parentCommentPosted,
	})
	return &pb.CreateTrackerIssueResponse{Issue: toProtoIssue(created)}, nil
}

// trackerIssueCreatedAuditDetail is the audit payload for
// tracker.issue_created: (tenant is the row's Username) skill, run,
// model, project, issue, parent, depth.
type trackerIssueCreatedAuditDetail struct {
	Connection          string   `json:"connection"`
	Project             string   `json:"project"`
	Number              int64    `json:"number"`
	ParentNumber        int64    `json:"parent_number,omitempty"`
	Depth               int32    `json:"depth,omitempty"`
	RunID               string   `json:"run_id"`
	SkillID             string   `json:"skill_id,omitempty"`
	Model               string   `json:"model,omitempty"`
	Labels              []string `json:"labels,omitempty"`
	ParentCommentPosted bool     `json:"parent_comment_posted"`
	// LineageRecorded is false when a run's child was created upstream but
	// its tracker_issue_lineage row could not be written (it is then not
	// counted for depth/fan-out and needs operator attention). Always
	// false for an operator token, which records no lineage by design.
	LineageRecorded bool `json:"lineage_recorded"`
}

// postCreateTimeout bounds the detached back-link + audit writes that
// follow a successful upstream create.
const postCreateTimeout = 15 * time.Second

// composeIssueBody builds the body sent upstream: the sanitized agent
// text, a parent link, and the identity stamp. The parent link is a
// bare "#N" on both providers — GitHub and GitLab both resolve it to an
// issue in the same project ("!N" is a GitLab merge request, never an
// issue). id comes from the verified token only, never from the request.
func composeIssueBody(agentBody string, parent int64, id tracker.Identity) string {
	var b strings.Builder
	if body := strings.TrimSpace(tracker.Sanitize(agentBody)); body != "" {
		b.WriteString(body)
		b.WriteString("\n\n")
	}
	if parent > 0 {
		fmt.Fprintf(&b, "Parent: #%d\n\n", parent)
	}
	b.WriteString(tracker.Stamp(id, tracker.KindIssue))
	return b.String()
}

// sanitizeIssueTitle collapses the agent-supplied title to one trimmed
// line and runs it through the same Sanitize as every other agent text.
func sanitizeIssueTitle(title string) string {
	title = strings.NewReplacer("\r", " ", "\n", " ").Replace(title)
	return strings.TrimSpace(tracker.Sanitize(title))
}

// dedupeLabels trims and de-duplicates, preserving first-seen order.
// Empty entries are kept (CheckLabels rejects them) rather than
// silently dropped — an agent passing "" is a bug worth surfacing.
func dedupeLabels(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, l := range in {
		l = strings.TrimSpace(l)
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// trimLabels trims surrounding whitespace from each label, keeping order
// and empties (CheckLabels rejects those).
func trimLabels(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, l := range in {
		out[i] = strings.TrimSpace(l)
	}
	return out
}

func appendUniqueLabel(labels []string, label string) []string {
	for _, l := range labels {
		if l == label {
			return labels
		}
	}
	return append(labels, label)
}
