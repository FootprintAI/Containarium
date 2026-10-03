package server

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentengine"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestBuildAgentSeedScript(t *testing.T) {
	seedDir := seedDirFor("run-1")
	script := buildAgentSeedScript(seedDir, "be helpful", "tok-123", `{"q":"hi"}`, `{"id":"x"}`)

	for _, want := range []string{
		"set -euo pipefail",
		"umask 077",
		"mkdir -p " + seedDir,
		seedDir + "/system_prompt.txt",
		seedDir + "/token",
		seedDir + "/input.json",
		seedDir + "/agent-card.json",
		"chmod 600 " + seedDir + "/token",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("seed script missing %q\n---\n%s", want, script)
		}
	}
}

func TestBuildAgentSeedScriptDefaultsInput(t *testing.T) {
	script := buildAgentSeedScript(seedDirFor("run-1"), "p", "t", "", "")
	if !strings.Contains(script, "'{}'") {
		t.Errorf("empty input should default to {}, got:\n%s", script)
	}
}

// TestSendAgentTaskRejectsDisallowedPeer is the moat as a test: an agent whose
// allowed_peers does not include the target is rejected at the API boundary,
// BEFORE any A2A send is attempted. The caller identity is taken from the
// authenticated token subject (agent-<skill-id>), not the caller-asserted
// field, so an agent box can't spoof a different caller to bypass the gate.
func TestSendAgentTaskRejectsDisallowedPeer(t *testing.T) {
	// hello-agent ships with allowed_peers: [] (a leaf), so every peer is denied.
	s := &AgentSkillServer{catalog: skills.GetDefault()}

	// Authenticate as the agent box itself; agents:call scope present.
	ctx := auth.ContextWithTestSubjectScopes(
		context.Background(), "agent-hello-agent", nil, []string{auth.ScopeAgentsCall})

	// from_skill_id deliberately lies ("admin-ish") — the authenticated subject
	// must win, so the call is still denied.
	_, err := s.SendAgentTask(ctx, &pb.SendAgentTaskRequest{
		FromSkillId: "some-privileged-skill",
		ToPeerId:    "other-peer",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for a peer not in allowed_peers, got %v", err)
	}
}

// TestMintedAgentTokenScopes_CallerRestrictedToAgentsRunGetsNoResourceScopes
// is the #1676 regression: a caller holding only agents:run must not receive
// a token carrying a manifest scope it never held itself.
func TestMintedAgentTokenScopes_CallerRestrictedToAgentsRunGetsNoResourceScopes(t *testing.T) {
	skill := &pb.AgentSkill{Id: "hello-agent", AllowedScopes: []string{auth.ScopeContainersRead}}
	ctx := auth.ContextWithTestSubjectScopes(
		context.Background(), "some-caller", nil, []string{auth.ScopeAgentsRun})

	got := mintedAgentTokenScopes(ctx, skill)
	if len(got) != 0 {
		t.Fatalf("mintedAgentTokenScopes = %v, want no resource scopes for a caller holding only agents:run", got)
	}
}

// TestMintedAgentTokenScopes_ManifestScopeCallerLacksNeverGranted is the
// regression named explicitly in #1676's acceptance criteria: a manifest
// declaring a scope the caller doesn't hold must never produce a token
// carrying it.
func TestMintedAgentTokenScopes_ManifestScopeCallerLacksNeverGranted(t *testing.T) {
	skill := &pb.AgentSkill{
		Id:            "escalating-skill",
		AllowedScopes: []string{auth.ScopeContainersRead, auth.ScopeSecretsWrite},
	}
	ctx := auth.ContextWithTestSubjectScopes(
		context.Background(), "some-caller", nil, []string{auth.ScopeAgentsRun, auth.ScopeContainersRead})

	got := mintedAgentTokenScopes(ctx, skill)
	if slices.Contains(got, auth.ScopeSecretsWrite) {
		t.Fatalf("mintedAgentTokenScopes = %v; caller never held %q", got, auth.ScopeSecretsWrite)
	}
	if len(got) != 1 || got[0] != auth.ScopeContainersRead {
		t.Fatalf("mintedAgentTokenScopes = %v, want [%q]", got, auth.ScopeContainersRead)
	}
}

// TestMintedAgentTokenScopes_UnrestrictedCallerKeepsManifestUnchanged covers
// the Phase 1.7 backwards-compat path: a pre-scopes-claim caller (nil scopes)
// is unrestricted, so the manifest passes through as it did before #1676.
func TestMintedAgentTokenScopes_UnrestrictedCallerKeepsManifestUnchanged(t *testing.T) {
	skill := &pb.AgentSkill{Id: "hello-agent", AllowedScopes: []string{auth.ScopeContainersRead}}
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "some-caller", nil, nil)

	got := mintedAgentTokenScopes(ctx, skill)
	if len(got) != 1 || got[0] != auth.ScopeContainersRead {
		t.Fatalf("mintedAgentTokenScopes = %v, want manifest unchanged [%q]", got, auth.ScopeContainersRead)
	}
}

// TestMintedAgentTokenScopes_TrackerAdminNeverGranted is the fix for a
// gap caught in code review of #1924 (CWE-862): tracker:admin gates
// tracker connection CRUD, an operator decision that must never reach a
// bounded skill run — no matter how permissive the dispatching caller or
// the skill manifest's own allowed_scopes are. Covers both the
// unrestricted-caller path (IntersectScopes would otherwise pass the
// manifest through unchanged) and the explicit-caller-holds-it path.
func TestMintedAgentTokenScopes_TrackerAdminNeverGranted(t *testing.T) {
	skill := &pb.AgentSkill{
		Id:            "misconfigured-skill",
		AllowedScopes: []string{auth.ScopeContainersRead, auth.ScopeTrackerAdmin},
	}

	t.Run("unrestricted caller", func(t *testing.T) {
		ctx := auth.ContextWithTestSubjectScopes(context.Background(), "some-caller", nil, nil)
		got := mintedAgentTokenScopes(ctx, skill)
		if slices.Contains(got, auth.ScopeTrackerAdmin) {
			t.Fatalf("mintedAgentTokenScopes = %v, must never carry tracker:admin", got)
		}
		if !slices.Contains(got, auth.ScopeContainersRead) {
			t.Fatalf("mintedAgentTokenScopes = %v, want containers:read still granted (only tracker:admin is stripped)", got)
		}
	})

	t.Run("caller explicitly holds tracker:admin", func(t *testing.T) {
		ctx := auth.ContextWithTestSubjectScopes(context.Background(), "some-caller", nil,
			[]string{auth.ScopeContainersRead, auth.ScopeTrackerAdmin})
		got := mintedAgentTokenScopes(ctx, skill)
		if slices.Contains(got, auth.ScopeTrackerAdmin) {
			t.Fatalf("mintedAgentTokenScopes = %v, must never carry tracker:admin even when the caller holds it", got)
		}
	})
}

// TestSendAgentTaskRequiresCallScope confirms the agents:call gate.
func TestSendAgentTaskRequiresCallScope(t *testing.T) {
	s := &AgentSkillServer{catalog: skills.GetDefault()}
	// Authenticated, but without agents:call.
	ctx := auth.ContextWithTestSubjectScopes(
		context.Background(), "agent-hello-agent", nil, []string{auth.ScopeAgentsRead})
	_, err := s.SendAgentTask(ctx, &pb.SendAgentTaskRequest{ToPeerId: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied without agents:call, got %v", err)
	}
}

// TestMintedAgentAct_DerivedFromAuthenticatedCaller is the #1677 AC
// "RunAgentSkill populates it at mint": a single-hop caller (a human/CLI
// token with no act of its own) produces a depth-1 chain naming them.
func TestMintedAgentAct_DerivedFromAuthenticatedCaller(t *testing.T) {
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	got := mintedAgentAct(ctx)
	if got == nil {
		t.Fatal("mintedAgentAct = nil, want a chain naming the authenticated caller")
	}
	if got.Subject != "alice" {
		t.Errorf("got.Subject = %q, want alice", got.Subject)
	}
	if got.Act != nil {
		t.Errorf("got.Act = %+v, want nil (caller had no delegation of its own)", got.Act)
	}
}

// TestMintedAgentAct_NestsCallersOwnAct is the #1677 AC "a second hop nests
// rather than overwrites": a caller that is itself a derived agent token
// (its own act names a human) produces a depth-2 chain wrapping both,
// never one that drops the human by overwriting with just the immediate
// caller.
func TestMintedAgentAct_NestsCallersOwnAct(t *testing.T) {
	callerAct := &auth.Actor{Subject: "alice"}
	ctx := auth.ContextWithTestSubjectAct(context.Background(), "agent-relay-agent", nil, callerAct)

	got := mintedAgentAct(ctx)
	if got == nil {
		t.Fatal("mintedAgentAct = nil, want a chain")
	}
	if got.Subject != "agent-relay-agent" {
		t.Errorf("got.Subject = %q, want agent-relay-agent", got.Subject)
	}
	if got.Act == nil || got.Act.Subject != "alice" {
		t.Fatalf("got.Act = %+v, want {Subject: alice} — the human must not be dropped", got.Act)
	}
}

// TestMintedAgentAct_UnauthenticatedContextReturnsNil covers the defensive
// case (unreachable in production once RequireScope has already run, but a
// public contract of this standalone function): no authenticated subject in
// ctx means nothing meaningful to record, not a garbage/zero-value Actor.
func TestMintedAgentAct_UnauthenticatedContextReturnsNil(t *testing.T) {
	if got := mintedAgentAct(context.Background()); got != nil {
		t.Errorf("mintedAgentAct(unauthenticated ctx) = %+v, want nil", got)
	}
}

// TestMintedAgentAct_IgnoresRequestFields is the #1677 anti-forgery AC,
// made explicit: mintedAgentAct's signature takes only ctx — there is no
// request parameter for a caller to inject an act through. This test pins
// that contract so a future refactor can't silently add one; it is the
// structural counterpart to the behavioral round-trip tests in
// internal/auth/delegation_test.go.
func TestMintedAgentAct_IgnoresRequestFields(t *testing.T) {
	fn := reflect.TypeOf(mintedAgentAct)
	if fn.NumIn() != 1 || fn.In(0).String() != "context.Context" {
		t.Fatalf("mintedAgentAct signature = %v, want func(context.Context) *auth.Actor — "+
			"any additional parameter (e.g. a request) would be a place for a caller to forge act", fn)
	}
}

func TestAgentNetworkPolicyConfigDomains(t *testing.T) {
	t.Run("defaults to the model providers when unset", func(t *testing.T) {
		_ = os.Unsetenv("CONTAINARIUM_AGENT_EGRESS_DOMAINS")
		_, domains, _ := agentNetworkPolicyConfig()
		// The provider defaults: Anthropic, OpenAI, and Gemini (the Gemini engine
		// added generativelanguage.googleapis.com so an ENFORCE policy doesn't
		// strand a Gemini agent). Assert against the source-of-truth slice.
		if len(domains) != len(defaultAgentEgressDomains) || domains[0] != "api.anthropic.com" {
			t.Errorf("default domains = %v, want %v", domains, defaultAgentEgressDomains)
		}
	})
	t.Run("operator override wins", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_AGENT_EGRESS_DOMAINS", "api.example.com, llm.internal")
		_, domains, _ := agentNetworkPolicyConfig()
		if len(domains) != 2 || domains[0] != "api.example.com" || domains[1] != "llm.internal" {
			t.Errorf("override domains = %v", domains)
		}
	})
}

func TestCompileAllowedPeersPolicySetsDomains(t *testing.T) {
	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a"},
		func(string) (string, bool) { return "10.0.0.5", true },
		nil, []string{"api.anthropic.com"}, "", true)
	if len(p.EgressDomains) != 1 || p.EgressDomains[0] != "api.anthropic.com" {
		t.Errorf("egress_domains = %v, want [api.anthropic.com]", p.EgressDomains)
	}
}

func TestCompileAllowedPeersPolicy_GatewayPinning(t *testing.T) {
	// #674 inc 4: with a gatewayCIDR set, the box's model egress is the gateway
	// host and the direct provider domains are DROPPED — so it can't bypass the
	// gateway. Peers + platform CIDRs are still allowed.
	resolve := func(string) (string, bool) { return "10.0.0.5", true }
	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a"}, resolve,
		nil, []string{"api.anthropic.com", "api.openai.com"}, "10.100.0.1/32", true)

	if len(p.EgressDomains) != 0 {
		t.Errorf("gateway mode must drop direct provider domains, got %v", p.EgressDomains)
	}
	if !slices.Contains(p.EgressCidrs, "10.100.0.1/32") {
		t.Errorf("gateway host must be in egress cidrs, got %v", p.EgressCidrs)
	}
	if !slices.Contains(p.EgressCidrs, "10.0.0.5/32") {
		t.Errorf("peer must still be allowed, got %v", p.EgressCidrs)
	}
}

func TestCompileAllowedPeersPolicy_NoGatewayKeepsDomains(t *testing.T) {
	// Direct mode (no gatewayCIDR): provider domains are served as before, and
	// the gateway host is NOT injected.
	resolve := func(string) (string, bool) { return "10.0.0.5", true }
	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a"}, resolve,
		nil, []string{"api.anthropic.com"}, "", false)
	if len(p.EgressDomains) != 1 || p.EgressDomains[0] != "api.anthropic.com" {
		t.Errorf("direct mode must keep provider domains, got %v", p.EgressDomains)
	}
	if slices.Contains(p.EgressCidrs, "10.100.0.1/32") {
		t.Errorf("no gateway host should be injected in direct mode, got %v", p.EgressCidrs)
	}
}

func TestSetGatewayProvisioning_EgressCIDR(t *testing.T) {
	s := &AgentSkillServer{}
	s.SetGatewayProvisioning("anthropic", 8080, []byte("secret"), "10.100.0.1", nil, nil, nil)
	if s.gateway.egressCIDR != "10.100.0.1/32" {
		t.Errorf("egressCIDR = %q, want 10.100.0.1/32", s.gateway.egressCIDR)
	}
	// Empty host IP → no pinning CIDR (direct provider egress retained).
	s.SetGatewayProvisioning("anthropic", 8080, []byte("secret"), "", nil, nil, nil)
	if s.gateway.egressCIDR != "" {
		t.Errorf("empty hostIP must yield no egressCIDR, got %q", s.gateway.egressCIDR)
	}
}

func TestParseArtifactOutput(t *testing.T) {
	t.Run("output", func(t *testing.T) {
		out, err := parseArtifactOutput([]byte(`{"outputJson":"{\"ok\":true}","engine":"claude","model":"claude-opus-4-8"}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != `{"ok":true}` {
			t.Errorf("output = %q", out)
		}
	})
	t.Run("error field surfaces", func(t *testing.T) {
		_, err := parseArtifactOutput([]byte(`{"outputJson":"","error":"model egress blocked"}`))
		if err == nil || !strings.Contains(err.Error(), "egress") {
			t.Errorf("expected the artifact error to surface, got %v", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		if _, err := parseArtifactOutput([]byte("not json")); err == nil {
			t.Error("expected decode error for malformed artifact")
		}
	})
}

func TestAgentRuntimeReleaseTag(t *testing.T) {
	// version.GetVersion() is the bare semver at runtime (the release workflow
	// builds with VERSION=${tag#v}); the recipe needs the v-prefixed git tag or
	// the artifact URLs 404 and box assembly silently skips. The helper must
	// re-add the prefix without double-prefixing an already-tagged value.
	got := agentRuntimeReleaseTag()
	if !strings.HasPrefix(got, "v") {
		t.Errorf("agentRuntimeReleaseTag() = %q, want a v-prefixed tag", got)
	}
	if strings.HasPrefix(got, "vv") {
		t.Errorf("agentRuntimeReleaseTag() = %q, double-prefixed", got)
	}
}

func TestGenTraceID(t *testing.T) {
	a, b := genTraceID(), genTraceID()
	if len(a) != 32 { // 16 bytes hex
		t.Errorf("trace id len = %d, want 32", len(a))
	}
	if a == "" || a == b {
		t.Errorf("trace ids should be non-empty and unique: %q %q", a, b)
	}
}

func TestAuditHopNilStoreNoPanic(t *testing.T) {
	// With no audit store wired, auditHop must be a safe no-op.
	s := &AgentSkillServer{}
	s.auditHop(context.Background(), "trace", "from", "to", "delivered", "")
}

// #1678 — auditAttributionFromContext is what makes auditHop's "record both
// the agent and the dispatching human" AC true; it's unit-tested directly
// since auditHop itself only runs against a real *audit.Store.

func TestAuditAttributionFromContext_NoDelegation(t *testing.T) {
	ctx := auth.ContextWithTestSubject(context.Background(), "agent-hello-agent", "user")
	actor, chain, tokenID := auditAttributionFromContext(ctx)
	if actor != "" || chain != "" || tokenID != "" {
		t.Fatalf("got actor=%q chain=%q tokenID=%q, want all empty for a non-delegated context", actor, chain, tokenID)
	}
}

func TestAuditAttributionFromContext_ResolvesRootActor(t *testing.T) {
	act := &auth.Actor{Subject: "agent-relay-agent", Act: &auth.Actor{Subject: "human-alice"}}
	ctx := auth.ContextWithTestSubjectAct(context.Background(), "agent-hello-agent", []string{"user"}, act)

	actor, chain, _ := auditAttributionFromContext(ctx)
	if actor != "human-alice" {
		t.Fatalf("actor = %q, want the root human human-alice", actor)
	}
	if !strings.Contains(chain, "human-alice") || !strings.Contains(chain, "agent-relay-agent") {
		t.Fatalf("delegationChain = %q, want the full chain serialized", chain)
	}
}

func TestAuditAttributionFromContext_ResolvesTokenID(t *testing.T) {
	ctx := auth.ContextWithTestSubject(context.Background(), "agent-hello-agent", "user")
	ctx = auth.ContextWithTestJTI(ctx, "jti-abc123")

	_, _, tokenID := auditAttributionFromContext(ctx)
	if tokenID != "jti-abc123" {
		t.Fatalf("tokenID = %q, want jti-abc123", tokenID)
	}
}

func TestBuildAgentSeedScriptEscapesSingleQuotes(t *testing.T) {
	// A system prompt containing a single quote must be escaped so it can't
	// break out of the shell-quoted printf argument.
	script := buildAgentSeedScript(seedDirFor("run-1"), "don't panic", "t", "{}", "{}")
	if strings.Contains(script, "don't") && !strings.Contains(script, `don'\''t`) {
		t.Errorf("single quote not escaped in seed script:\n%s", script)
	}
}

func TestCompileAllowedPeersPolicy(t *testing.T) {
	running := map[string]string{"peer-a": "10.0.0.5", "peer-b": "10.0.0.6"}
	resolve := func(id string) (string, bool) { ip, ok := running[id]; return ip, ok }

	// peer-c is not running, so it must be omitted from the allowlist.
	p := compileAllowedPeersPolicy("agent-caller", []string{"peer-a", "peer-b", "peer-c"}, resolve, nil, nil, "", false)

	if p.Tenant != "agent-caller" {
		t.Errorf("tenant = %q, want agent-caller", p.Tenant)
	}
	if p.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY {
		t.Errorf("mode = %v, want LOG_ONLY (observe-only until enforcement is armed)", p.Mode)
	}
	if p.AllowMetadata {
		t.Error("allow_metadata must be false for an agent box")
	}
	if p.AllowIntraTenant {
		t.Error("allow_intra_tenant must be false (deny-by-default)")
	}
	want := []string{"10.0.0.5/32", "10.0.0.6/32"}
	if len(p.EgressCidrs) != len(want) {
		t.Fatalf("egress_cidrs = %v, want %v", p.EgressCidrs, want)
	}
	for i := range want {
		if p.EgressCidrs[i] != want[i] {
			t.Errorf("egress_cidrs[%d] = %q, want %q", i, p.EgressCidrs[i], want[i])
		}
	}

	// #2140: each peer /32 stays reachable, but not on its A2A port — the only
	// thing that may post a task to a peer is the daemon (D1), so the box gets a
	// deny rule for tcp/8674 on every peer it can otherwise reach.
	wantDeny := []*pb.NetworkPolicyDenyRule{
		{Cidr: "10.0.0.5/32", Port: a2aPort, Proto: "tcp"},
		{Cidr: "10.0.0.6/32", Port: a2aPort, Proto: "tcp"},
	}
	if len(p.DenyRules) != len(wantDeny) {
		t.Fatalf("deny_rules = %v, want %v", p.DenyRules, wantDeny)
	}
	for i, w := range wantDeny {
		g := p.DenyRules[i]
		if g.GetCidr() != w.Cidr || g.GetPort() != w.Port || g.GetProto() != w.Proto {
			t.Errorf("deny_rules[%d] = {%s %d %s}, want {%s %d %s}", i, g.GetCidr(), g.GetPort(), g.GetProto(), w.Cidr, w.Port, w.Proto)
		}
		if g.GetNote() == "" {
			t.Errorf("deny_rules[%d] has no note; the audit event should say why the hop was refused", i)
		}
		if g.GetExpiresAt() != "" {
			t.Errorf("deny_rules[%d] expires_at = %q, want no expiry", i, g.GetExpiresAt())
		}
	}
}

// TestCompileAllowedPeersPolicy_A2ADenySurvivesCompile runs the agent-skill
// policy through the same validate/normalize path applyAllowedPeersPolicy uses
// before storing it, and then into the kernel map entries, so the A2A-port
// deny is proven to reach the deny_cidr map scoped to tcp/8674 — not collapsed
// to a whole-host block, and not dropped.
func TestCompileAllowedPeersPolicy_A2ADenySurvivesCompile(t *testing.T) {
	resolve := func(string) (string, bool) { return "10.0.0.5", true }
	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a"}, resolve,
		[]string{"10.0.1.1/32"}, nil, "10.100.0.1/32", true)

	c, err := netpolicy.Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !slices.Contains(c.EgressCIDRs, netip.MustParsePrefix("10.0.0.5/32")) {
		t.Errorf("peer /32 must remain an egress allow, got %v", c.EgressCIDRs)
	}
	entries, err := netbpf.CompileDeny(7, c)
	if err != nil {
		t.Fatalf("CompileDeny: %v", err)
	}
	want := netbpf.DenyEntry{PrefixLen: 64, TenantID: 7, Addr: [4]byte{10, 0, 0, 5}, Port: 8674, Proto: 6}
	if len(entries) != 1 || entries[0] != want {
		t.Fatalf("deny entries = %+v, want exactly [%+v] (peer only — never the daemon/gateway CIDRs)", entries, want)
	}
}

func TestCompileAllowedPeersPolicyNoneRunning(t *testing.T) {
	// No peer is running -> empty allowlist (the caller skips installing it
	// rather than denying all egress under a future ENFORCE).
	p := compileAllowedPeersPolicy("t", []string{"x", "y"}, func(string) (string, bool) { return "", false }, nil, nil, "", false)
	if len(p.EgressCidrs) != 0 {
		t.Errorf("expected no egress cidrs when no peers run, got %v", p.EgressCidrs)
	}
	if len(p.DenyRules) != 0 {
		t.Errorf("expected no deny rules when no peers run, got %v", p.DenyRules)
	}
}

func TestCompileAllowedPeersPolicyEnforceAndExtraCIDRs(t *testing.T) {
	resolve := func(id string) (string, bool) {
		if id == "peer-a" {
			return "10.0.0.5", true
		}
		return "", false
	}
	// Armed ENFORCE + platform egress (e.g. daemon + DNS) so the agent isn't
	// stranded by a peer-only allowlist.
	extra := []string{"10.0.1.1/32", "10.0.1.2/32"}
	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a"}, resolve, extra, nil, "", true)

	if p.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE {
		t.Errorf("mode = %v, want ENFORCE when armed", p.Mode)
	}
	want := []string{"10.0.0.5/32", "10.0.1.1/32", "10.0.1.2/32"}
	if len(p.EgressCidrs) != len(want) {
		t.Fatalf("egress_cidrs = %v, want %v", p.EgressCidrs, want)
	}
	for i := range want {
		if p.EgressCidrs[i] != want[i] {
			t.Errorf("egress_cidrs[%d] = %q, want %q", i, p.EgressCidrs[i], want[i])
		}
	}
}

func TestCompileAllowedPeersPolicyLeafIsDefaultDeny(t *testing.T) {
	// #750: a leaf skill (no allowed_peers) in direct mode (no gateway) still
	// gets a restrictive policy — provider domains only, with metadata and
	// intra-tenant denied. applyAllowedPeersPolicy now installs this for every
	// box (it no longer short-circuits on "no peers"), so under ENFORCE a leaf
	// box is locked down instead of left with no eBPF program.
	p := compileAllowedPeersPolicy("agent-x", nil, func(string) (string, bool) { return "", false },
		nil, defaultAgentEgressDomains, "", false)
	if len(p.EgressCidrs) != 0 {
		t.Errorf("leaf: expected no egress cidrs, got %v", p.EgressCidrs)
	}
	if len(p.EgressDomains) != len(defaultAgentEgressDomains) {
		t.Errorf("leaf: expected the provider domains as the only egress, got %v", p.EgressDomains)
	}
	if p.AllowIntraTenant {
		t.Error("leaf: intra-tenant must be denied")
	}
	if p.AllowMetadata {
		t.Error("leaf: metadata must be denied")
	}
}

// #2222: engineForProvider and engineEnvPrefix moved into internal/agentengine
// (Provider/ForProvider, Resolve) and into runtimeEnvPrefix (rendering only)
// respectively. The provider<->engine mapping table they pinned now lives in
// agentengine's TestProviderRoundTrip; runtimeEnvPrefix's own rendering rules
// are pinned below. SetGatewayProvisioning now also populates
// engines.DefaultProvider from gatewayPrimaryProvider's own provider string.

func TestSetGatewayProvisioning_PopulatesDefaultProvider(t *testing.T) {
	s := &AgentSkillServer{}
	s.SetGatewayProvisioning("gemini", 8080, []byte("secret"), "", map[string]bool{"gemini": true}, nil, nil)
	if s.gateway.engines.DefaultProvider != "gemini" {
		t.Errorf("engines.DefaultProvider = %q, want gemini", s.gateway.engines.DefaultProvider)
	}
	if !s.gateway.engines.GlobalProviders["gemini"] {
		t.Errorf("engines.GlobalProviders = %v, want gemini present", s.gateway.engines.GlobalProviders)
	}
}

func TestRuntimeEnvPrefix(t *testing.T) {
	// Direct mode, no engine named: no engine pin at all — the box's own
	// default decides. Byte-identical to every box that predates this field.
	if got := runtimeEnvPrefix(agentengine.Resolved{}, ""); got != "" {
		t.Errorf("unspecified: prefix = %q, want empty", got)
	}
	// A resolved engine is always pinned (#748's original fix, now computed
	// by agentengine.Resolve upstream instead of a daemon-wide lookup here).
	gemini := agentengine.Resolved{Engine: pb.AgentEngine_AGENT_ENGINE_GEMINI, Provider: "gemini", Default: true}
	if got := runtimeEnvPrefix(gemini, ""); got != "CONTAINARIUM_AGENT_ENGINE=gemini " {
		t.Errorf("gemini default: prefix = %q, want CONTAINARIUM_AGENT_ENGINE=gemini ", got)
	}
	// Q1 (docs/product/agent-router.md): the manifest's model is exported
	// only when the engine was NAMED by the manifest (Default=false) — a
	// default-resolved engine (Default=true) never exports the model, even
	// when one is set, so an unspecified-engine skill cannot start failing
	// on a daemon whose default engine doesn't match its pinned model.
	named := agentengine.Resolved{Engine: pb.AgentEngine_AGENT_ENGINE_CODEX, Provider: "openai", Default: false}
	if got := runtimeEnvPrefix(named, "gpt-5"); got != "CONTAINARIUM_AGENT_ENGINE=codex CONTAINARIUM_AGENT_MODEL='gpt-5' " {
		t.Errorf("named engine with model: prefix = %q, want both exported", got)
	}
	if got := runtimeEnvPrefix(gemini, "claude-opus-4-8"); got != "CONTAINARIUM_AGENT_ENGINE=gemini " {
		t.Errorf("default-resolved engine must never export the manifest's model, got %q", got)
	}
}

func TestPeerAllowed(t *testing.T) {
	s := &AgentSkillServer{catalog: skills.GetDefault()}

	// hello-agent ships with allowed_peers: [] (leaf) — so any peer is denied.
	if s.peerAllowed("hello-agent", "some-peer") {
		t.Error("hello-agent has no allowed_peers; call should be denied")
	}
	// Empty caller (admin/operator direct call) is allowed — eBPF is the
	// boundary for box-originated traffic.
	if !s.peerAllowed("", "some-peer") {
		t.Error("empty caller should be allowed (not gated at this layer)")
	}
	// Unknown caller skill is allowed (not ours to gate here).
	if !s.peerAllowed("does-not-exist", "some-peer") {
		t.Error("unknown caller skill should not be gated here")
	}
}

// #2140: NetworkPolicyStore.Set deliberately drops deny rules (they are owned
// by MutateDenyRules), so the A2A-port denies must be written through
// MutateDenyRules or they never reach the store — and from there the kernel.
func TestStoreAgentSkillPolicy_PersistsA2ADenies(t *testing.T) {
	ctx := context.Background()
	store := NewMemNetworkPolicyStore()
	running := map[string]string{"peer-a": "10.0.0.5", "peer-b": "10.0.0.6"}
	resolve := func(id string) (string, bool) { ip, ok := running[id]; return ip, ok }

	denyCIDRs := func() []string {
		t.Helper()
		got, err := store.Get(ctx, "agent-x")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		var out []string
		for _, r := range got.GetDenyRules() {
			out = append(out, r.GetCidr()+":"+strconv.Itoa(int(r.GetPort()))+"/"+r.GetProto())
		}
		slices.Sort(out)
		return out
	}

	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a", "peer-b"}, resolve, nil, defaultAgentEgressDomains, "", false)
	if err := storeAgentSkillPolicy(ctx, store, p); err != nil {
		t.Fatalf("storeAgentSkillPolicy: %v", err)
	}
	if got, want := denyCIDRs(), []string{"10.0.0.5/32:8674/tcp", "10.0.0.6/32:8674/tcp"}; !slices.Equal(got, want) {
		t.Fatalf("stored deny rules = %v, want %v", got, want)
	}

	// An operator's own virtual patch on the tenant must survive a relaunch.
	if _, err := store.MutateDenyRules(ctx, "agent-x", func(rs []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) {
		return append(rs, &pb.NetworkPolicyDenyRule{Cidr: "203.0.113.9/32", Note: "CVE-x"}), nil
	}); err != nil {
		t.Fatalf("operator MutateDenyRules: %v", err)
	}

	// Relaunch with only peer-a: peer-b's A2A deny is ours and stale — drop it;
	// the operator's rule is not ours — keep it.
	p = compileAllowedPeersPolicy("agent-x", []string{"peer-a"}, resolve, nil, defaultAgentEgressDomains, "", false)
	if err := storeAgentSkillPolicy(ctx, store, p); err != nil {
		t.Fatalf("storeAgentSkillPolicy (relaunch): %v", err)
	}
	if got, want := denyCIDRs(), []string{"10.0.0.5/32:8674/tcp", "203.0.113.9/32:0/"}; !slices.Equal(got, want) {
		t.Fatalf("after relaunch deny rules = %v, want %v", got, want)
	}
}

func TestMergeA2ADenyRules_OperatorRuleOnSameHostWins(t *testing.T) {
	// The kernel holds one deny entry per CIDR. An operator rule already on a
	// peer's /32 (say, a whole-host block) owns that slot: the A2A deny must not
	// overwrite it, which would silently narrow the operator's block to one port.
	op := &pb.NetworkPolicyDenyRule{Cidr: "10.0.0.5/32", Note: "operator: isolate host"}
	desired := []*pb.NetworkPolicyDenyRule{
		{Cidr: "10.0.0.5/32", Port: a2aPort, Proto: "tcp", Note: a2aDenyNote},
		{Cidr: "10.0.0.6/32", Port: a2aPort, Proto: "tcp", Note: a2aDenyNote},
	}
	got := mergeA2ADenyRules([]*pb.NetworkPolicyDenyRule{op}, desired)
	if len(got) != 2 {
		t.Fatalf("merged = %v, want the operator rule + the 10.0.0.6 A2A deny", got)
	}
	if got[0] != op {
		t.Errorf("operator rule on 10.0.0.5/32 was replaced: %v", got[0])
	}
	if got[1].GetCidr() != "10.0.0.6/32" || got[1].GetPort() != a2aPort {
		t.Errorf("A2A deny for 10.0.0.6/32 missing: %v", got[1])
	}
}
