package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/modelgateway"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type captureAuditLog struct{ entries []*audit.AuditEntry }

func (c *captureAuditLog) Log(_ context.Context, e *audit.AuditEntry) error {
	c.entries = append(c.entries, e)
	return nil
}

func TestGatewayInboundAudit_WritesTypedDetailWithoutContent(t *testing.T) {
	log := &captureAuditLog{}
	err := gatewayInboundAudit{log: log}.RecordInboundBlock(context.Background(), modelgateway.InboundBlock{
		Tenant: "tenant-a", SkillID: "s1", Provider: "openai", Model: "m",
		Reason: guardrail.InboundReasonFinding, Kinds: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PROMPT_INJECTION},
		Findings: 2, EngineID: guardrail.RulesEngineID, PolicyRevision: 7,
	})
	if err != nil || len(log.entries) != 1 {
		t.Fatalf("err=%v entries=%d", err, len(log.entries))
	}
	e := log.entries[0]
	if e.Action != modelGatewayInboundBlockAction || e.Username != "tenant-a" || e.ResourceID != "tenant-a" {
		t.Errorf("entry attribution wrong: %+v", e)
	}
	var d inboundBlockAuditDetail
	if err := json.Unmarshal([]byte(e.Detail), &d); err != nil {
		t.Fatal(err)
	}
	if d.Reason != guardrail.InboundReasonFinding.String() || d.Findings != 2 || d.PolicyRevision != 7 || len(d.Kinds) != 1 || d.Provider != "openai" {
		t.Errorf("detail wrong: %+v", d)
	}
}

func TestNewGatewayInboundAudit_NilStoreIsNilInterface(t *testing.T) {
	if s := newGatewayInboundAudit(nil); s != nil {
		t.Errorf("nil store produced a non-nil sink: %#v", s)
	}
}

func TestGuardrailPolicyServer_OnChangeRunsOnlyAfterASuccessfulSet(t *testing.T) {
	s := NewGuardrailPolicyServer(guardrailpolicy.NewMemoryStore())
	called := 0
	s.SetOnChange(func() { called++ })
	if _, err := s.SetGuardrailPolicy(gpUserCtx(), gpRequest(0, gpSigner(1))); err == nil {
		t.Fatal("non-admin Set succeeded")
	}
	if called != 0 {
		t.Errorf("hook ran for a refused Set: %d", called)
	}
	if _, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0, gpSigner(1))); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Errorf("hook ran %d times after a successful Set, want 1", called)
	}
}
