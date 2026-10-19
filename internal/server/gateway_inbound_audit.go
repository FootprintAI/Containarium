package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/modelgateway"
)

// modelGatewayInboundBlockAction is the audit action of one response the
// model gateway's inbound scan blocked (#2367).
const modelGatewayInboundBlockAction = "model_gateway.inbound_block"

// inboundBlockAuditDetail is the Detail of a model_gateway.inbound_block
// entry: attribution, the typed reason, finding kinds and counts. Never the
// flagged text or the response body.
type inboundBlockAuditDetail struct {
	Skill          string   `json:"skill,omitempty"`
	Provider       string   `json:"provider"`
	Model          string   `json:"model,omitempty"`
	Reason         string   `json:"reason"`
	Kinds          []string `json:"kinds,omitempty"`
	Findings       int      `json:"findings"`
	EngineID       string   `json:"engine_id,omitempty"`
	PolicyRevision int64    `json:"policy_revision"`
}

// gatewayInboundAudit writes inbound blocks and baseline detections to the
// daemon's audit log. It satisfies modelgateway.InboundAuditSink; the gateway
// calls it from its audit worker, never on the request path.
type gatewayInboundAudit struct {
	log auditLogger
}

var _ modelgateway.InboundAuditSink = gatewayInboundAudit{}

func (a gatewayInboundAudit) RecordInboundBlock(ctx context.Context, b modelgateway.InboundBlock) error {
	d := inboundBlockAuditDetail{
		Skill: b.SkillID, Provider: b.Provider, Model: b.Model, Reason: b.Reason.String(),
		Findings: b.Findings, EngineID: b.EngineID, PolicyRevision: b.PolicyRevision,
	}
	for _, k := range b.Kinds {
		d.Kinds = append(d.Kinds, k.String())
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshal inbound block detail: %w", err)
	}
	return a.log.Log(ctx, &audit.AuditEntry{
		Username:     b.Tenant,
		Action:       modelGatewayInboundBlockAction,
		ResourceType: "model_gateway",
		ResourceID:   b.Tenant,
		Detail:       string(payload),
	})
}

// modelGatewayInboundDetectionAction is the audit action of one baseline
// rule that matched in a model response while no admin policy exists
// (#2736). Log-only: the response was delivered.
const modelGatewayInboundDetectionAction = "model_gateway.inbound_detection"

// inboundDetectionAuditDetail is the Detail of a
// model_gateway.inbound_detection entry: attribution, which policy flagged it,
// the rule id, kind and action, and the match count. Never the matched text.
type inboundDetectionAuditDetail struct {
	Skill    string `json:"skill,omitempty"`
	Provider string `json:"provider"`
	Model    string `json:"model,omitempty"`
	Policy   string `json:"policy"`
	RuleID   string `json:"rule_id"`
	Kind     string `json:"kind"`
	Action   string `json:"action"`
	Matches  int    `json:"matches"`
}

func (a gatewayInboundAudit) RecordInboundDetection(ctx context.Context, d modelgateway.InboundDetection) error {
	payload, err := json.Marshal(inboundDetectionAuditDetail{
		Skill: d.SkillID, Provider: d.Provider, Model: d.Model, Policy: "baseline",
		RuleID: string(d.RuleID), Kind: d.Kind.String(), Action: d.Action.String(), Matches: d.Matches,
	})
	if err != nil {
		return fmt.Errorf("marshal inbound detection detail: %w", err)
	}
	return a.log.Log(ctx, &audit.AuditEntry{
		Username:     d.Tenant,
		Action:       modelGatewayInboundDetectionAction,
		ResourceType: "model_gateway",
		ResourceID:   d.Tenant,
		Detail:       string(payload),
	})
}

// newGatewayInboundAudit returns the sink for a daemon audit store, or nil
// when there is none: the gateway then logs blocks only. The explicit nil
// check keeps a nil *audit.Store from becoming a non-nil interface.
func newGatewayInboundAudit(store *audit.Store) modelgateway.InboundAuditSink {
	if store == nil {
		return nil
	}
	return gatewayInboundAudit{log: store}
}
