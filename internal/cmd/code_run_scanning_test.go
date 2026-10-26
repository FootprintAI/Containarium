package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
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

// storeStatusAPI answers GetGuardrailStatus the way the daemon does: from the
// policy store through EffectiveStatus.
type storeStatusAPI struct{ fake *fakeGuardrailPolicyAPI }

func (s storeStatusAPI) GetGuardrailStatus() (*pb.GetGuardrailStatusResponse, error) {
	if s.fake.getErr != nil {
		return nil, s.fake.getErr
	}
	p, err := s.fake.store.Get(context.Background())
	return guardrailpolicy.EffectiveStatus(p, err)
}

func withStoreStatusAPI(t *testing.T, fake *fakeGuardrailPolicyAPI) {
	t.Helper()
	prev := newGuardrailStatusAPI
	newGuardrailStatusAPI = func() (guardrailStatusAPI, func(), error) { return storeStatusAPI{fake}, func() {}, nil }
	t.Cleanup(func() { newGuardrailStatusAPI = prev })
}

func TestReportModelTrafficScanning(t *testing.T) {
	gw := engine.GatewayCredential{Provider: "anthropic"}
	setPolicy := func(t *testing.T, fake *fakeGuardrailPolicyAPI, rules ...*pb.GuardrailRule) {
		t.Helper()
		if _, err := fake.store.Set(context.Background(), &pb.GuardrailPolicy{Rules: rules}, nil, "ops"); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("tenant key does not consult the server", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		fake.getErr = errors.New("must not be called")
		withStoreStatusAPI(t, fake)
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, engine.SecretCredential{Name: "ANTHROPIC_API_KEY"}), &out)
		if !strings.Contains(out.String(), "NOT SCANNED (the box's own provider key") {
			t.Errorf("got %q", out.String())
		}
	})
	t.Run("gateway, no policy configured reports the baseline scan", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		withStoreStatusAPI(t, fake)
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, gw), &out)
		if !strings.Contains(out.String(), "model traffic: BASELINE") || strings.Contains(out.String(), "NOT SCANNED") {
			t.Errorf("got %q", out.String())
		}
	})
	t.Run("gateway, policy without an inbound block rule stays unscanned", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		withStoreStatusAPI(t, fake)
		setPolicy(t, fake, &pb.GuardrailRule{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK})
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, gw), &out)
		if !strings.Contains(out.String(), "NOT SCANNED") || !strings.Contains(out.String(), "no inbound BLOCK rule") {
			t.Errorf("got %q", out.String())
		}
	})
	t.Run("gateway, inbound block rule", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		withStoreStatusAPI(t, fake)
		setPolicy(t, fake, &pb.GuardrailRule{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PROMPT_INJECTION, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK})
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, gw), &out)
		if !strings.Contains(out.String(), "model traffic: SCANNED") {
			t.Errorf("got %q", out.String())
		}
	})
	t.Run("gateway, server unreachable is unknown and not fatal", func(t *testing.T) {
		fake := withFakeGuardrailPolicyAPI(t)
		fake.getErr = errors.New("down")
		withStoreStatusAPI(t, fake)
		var out bytes.Buffer
		reportModelTrafficScanning(scanningEngine(t, gw), &out)
		if !strings.Contains(out.String(), "status unknown") {
			t.Errorf("got %q", out.String())
		}
	})
}
