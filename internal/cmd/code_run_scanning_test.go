package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun/engine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func scanningEngine(t *testing.T, cred engine.CredentialSource) engine.Engine {
	t.Helper()
	eng, err := engine.For(engine.NameClaude, engine.Options{Credential: cred})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestReportModelTrafficScanning(t *testing.T) {
	gw := engine.GatewayCredential{Provider: "anthropic"}
	t.Run("tenant key does not consult the server", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		fake.getErr = errors.New("must not be called")
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, engine.SecretCredential{Name: "ANTHROPIC_API_KEY"}), &out)
		if !strings.Contains(out.String(), "NOT SCANNED (the box's own provider key") {
			t.Errorf("got %q", out.String())
		}
	})
	t.Run("gateway, no policy", func(t *testing.T) {
		withFakeGuardrailPolicyAPI(t)
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, gw), &out)
		if !strings.Contains(out.String(), "no inbound BLOCK rule") {
			t.Errorf("got %q", out.String())
		}
	})
	t.Run("gateway, inbound block rule", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		_, err := fake.store.Set(context.Background(), &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
			{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PROMPT_INJECTION, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
		}}, nil, "ops")
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, gw), &out)
		if !strings.Contains(out.String(), "model traffic: SCANNED") {
			t.Errorf("got %q", out.String())
		}
	})
	t.Run("gateway, server unreachable is unknown and not fatal", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		fake.getErr = errors.New("down")
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, gw), &out)
		if !strings.Contains(out.String(), "status unknown") {
			t.Errorf("got %q", out.String())
		}
	})
}
