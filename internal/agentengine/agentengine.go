// Package agentengine resolves which agent engine (and which gateway
// provider) one skill run uses, given the manifest's own choice and the
// daemon's gateway state. It is the one place this rule lives (#2222,
// design: docs/architecture/agent-router.md) — every launch path a run can
// take (push run, crew member, pull-queue worker) and the status surface
// that reports readiness both call Resolve, so what the daemon reports as
// ready and what a run actually does cannot drift apart.
//
// This package is pure: Resolve takes an injected KeyResolver rather than
// reaching into a secrets store itself, so the whole decision table is a
// table-driven unit test with no database, no daemon, and no box.
package agentengine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/footprintai/containarium/internal/gatewayprovider"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Parse resolves a manifest/flag engine name ("claude", "codex", "gemini" —
// case-insensitive, trimmed) to its typed value. Unknown or empty input is an
// error listing the valid names — never a silent fall back to UNSPECIFIED. A
// skill that leaves the field unset carries AGENT_ENGINE_UNSPECIFIED directly
// (the proto zero value); Parse is for turning a NAME into that value, so it
// deliberately does not accept "" as meaning UNSPECIFIED.
func Parse(s string) (pb.AgentEngine, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "claude":
		return pb.AgentEngine_AGENT_ENGINE_CLAUDE, nil
	case "codex":
		return pb.AgentEngine_AGENT_ENGINE_CODEX, nil
	case "gemini":
		return pb.AgentEngine_AGENT_ENGINE_GEMINI, nil
	default:
		return pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED, fmt.Errorf("unknown agent engine %q (one of: %s)", s, strings.Join(Names(), ", "))
	}
}

// All lists every concrete (non-UNSPECIFIED) engine, in enum order.
func All() []pb.AgentEngine {
	return []pb.AgentEngine{
		pb.AgentEngine_AGENT_ENGINE_CLAUDE,
		pb.AgentEngine_AGENT_ENGINE_CODEX,
		pb.AgentEngine_AGENT_ENGINE_GEMINI,
	}
}

// Names lists every engine Parse accepts, for error messages and flag help.
func Names() []string {
	out := make([]string, 0, len(All()))
	for _, e := range All() {
		out = append(out, EnvValue(e))
	}
	sort.Strings(out)
	return out
}

// EnvValue is the exact string CONTAINARIUM_AGENT_ENGINE carries for e, i.e.
// the value the agent-runtime's own pickEngine switch matches on
// (agent-runtime/src/index.ts). "" for UNSPECIFIED — callers use that as the
// "do not export this variable" signal rather than a literal value.
func EnvValue(e pb.AgentEngine) string {
	switch e {
	case pb.AgentEngine_AGENT_ENGINE_CLAUDE:
		return "claude"
	case pb.AgentEngine_AGENT_ENGINE_CODEX:
		return "codex"
	case pb.AgentEngine_AGENT_ENGINE_GEMINI:
		return "gemini"
	default:
		return ""
	}
}

// Provider is the gateway provider e speaks. ok=false for UNSPECIFIED (it
// names no provider of its own — Resolve fills one in from the gateway's
// default) and for any engine this package doesn't know.
func Provider(e pb.AgentEngine) (name string, ok bool) {
	switch e {
	case pb.AgentEngine_AGENT_ENGINE_CLAUDE:
		return "anthropic", true
	case pb.AgentEngine_AGENT_ENGINE_CODEX:
		return "openai", true
	case pb.AgentEngine_AGENT_ENGINE_GEMINI:
		return "gemini", true
	default:
		return "", false
	}
}

// ForProvider inverts Provider. UNSPECIFIED for a provider no engine speaks
// (e.g. an operator-registered OpenAI-compatible upstream with its own
// provider name) — see docs/architecture/agent-router.md "What changes at
// 10x" for engines whose provider is not fixed.
func ForProvider(provider string) pb.AgentEngine {
	for _, e := range All() {
		if p, _ := Provider(e); p == provider {
			return e
		}
	}
	return pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED
}

// KeyResolver reports whether a usable provider key exists for one key
// owner, without ever handing the key's value back to this package — Resolve
// only ever inspects the boolean. Any type satisfying modelgateway.KeyResolver
// (KeyFor(ctx, keyOwner, provider) (string, bool)) already implements this.
type KeyResolver interface {
	KeyFor(ctx context.Context, keyOwner, provider string) (string, bool)
}

// Gateway is the daemon's model-gateway state, as Resolve needs to see it. A
// nil *Gateway means direct mode (the daemon serves no gateway): boxes run
// with whatever credential their own environment supplies, and Resolve never
// refuses a run in that mode.
type Gateway struct {
	// DefaultProvider is what AGENT_ENGINE_UNSPECIFIED resolves to — today's
	// gatewayPrimaryProvider(keys): the first of anthropic/openai/gemini the
	// daemon holds a global key for. Empty if the daemon holds no global key
	// at all (gateway still "enabled" via an operator-registered upstream).
	DefaultProvider string
	// GlobalProviders is the set of providers the daemon holds a key for in
	// its own environment (not per key-owner). A provider in this set is
	// ready for every caller, with no per-owner lookup needed.
	GlobalProviders map[string]bool
	// Keys resolves a per-owner key when GlobalProviders doesn't already
	// cover the provider. Nil when the daemon has no per-owner store (no
	// Postgres) — then only GlobalProviders can make a provider ready.
	Keys KeyResolver
}

// Resolved is the engine and provider one run actually uses.
type Resolved struct {
	// Engine is never a value Parse would reject; it IS AGENT_ENGINE_UNSPECIFIED
	// exactly when no CONTAINARIUM_AGENT_ENGINE should be exported for this run
	// (direct mode with no engine named).
	Engine pb.AgentEngine
	// Provider is the gateway provider the run's token is bound to; "" in
	// direct mode, where there is no gateway to bind a token to.
	Provider string
	// Default is true when `want` was UNSPECIFIED and this result came from
	// the gateway's default provider (or, in direct mode, from there being no
	// engine named at all) rather than the manifest naming one explicitly.
	// Callers use this to decide whether to export CONTAINARIUM_AGENT_MODEL:
	// only when Default is false (Q1, docs/product/agent-router.md).
	Default bool
}

// NotReadyError is returned when a named engine's provider has no resolvable
// key, in gateway mode. Reason and Fix are meant to be read by a human — the
// same text a FailedPrecondition error and a ListAgentEngines row both show,
// so "why can't this run" and "why does this engine show as not ready" never
// say two different things for the same cause.
type NotReadyError struct {
	Engine   pb.AgentEngine
	Provider string
	KeyOwner string
	Reason   string
	Fix      string
}

func (e *NotReadyError) Error() string {
	return fmt.Sprintf("engine %s (provider %s) not ready: %s", EnvValue(e.Engine), e.Provider, e.Reason)
}

// Resolve turns a manifest's engine choice into the engine and provider one
// run actually uses, or a *NotReadyError when a named engine's provider has
// no key anywhere gw can see.
//
//	gw == nil (direct mode):
//	  want == UNSPECIFIED -> Engine=UNSPECIFIED, Provider="", Default=true
//	    (no CONTAINARIUM_AGENT_ENGINE exported — byte-identical to today)
//	  want named           -> Engine=want, Provider="", Default=false
//	    (exported as-is; NEVER refused — the daemon holds no key to check
//	    against, and direct mode is the box's own secrets deciding)
//
//	gw != nil (gateway mode):
//	  want == UNSPECIFIED -> Engine=ForProvider(gw.DefaultProvider),
//	    Provider=gw.DefaultProvider, Default=true (today's primary-provider
//	    pinning, unchanged)
//	  want named          -> provider := Provider(want); ready when
//	    gw.GlobalProviders[provider] (no owner lookup needed) or
//	    gw.Keys != nil && gw.Keys.KeyFor(ctx, keyOwner, provider) is ok;
//	    else *NotReadyError
func Resolve(ctx context.Context, want pb.AgentEngine, keyOwner string, gw *Gateway) (Resolved, error) {
	if gw == nil {
		if want == pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED {
			return Resolved{Engine: pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED, Default: true}, nil
		}
		return Resolved{Engine: want, Default: false}, nil
	}

	if want == pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED {
		return Resolved{
			Engine:   ForProvider(gw.DefaultProvider),
			Provider: gw.DefaultProvider,
			Default:  true,
		}, nil
	}

	provider, ok := Provider(want)
	if !ok {
		// Not reachable with a Parse-produced value, but a caller could in
		// principle hand Resolve a raw enum value Parse never returns (e.g.
		// from a future engine added to the proto before this package knows
		// its provider) — fail loudly rather than mint a token for "".
		return Resolved{}, fmt.Errorf("engine %v has no known gateway provider", want)
	}

	if gw.GlobalProviders[provider] {
		return Resolved{Engine: want, Provider: provider, Default: false}, nil
	}
	if gw.Keys != nil {
		if _, hasKey := gw.Keys.KeyFor(ctx, keyOwner, provider); hasKey {
			return Resolved{Engine: want, Provider: provider, Default: false}, nil
		}
	}

	return Resolved{}, &NotReadyError{
		Engine:   want,
		Provider: provider,
		KeyOwner: keyOwner,
		Reason:   fmt.Sprintf("no key for provider %s", provider),
		Fix:      fmt.Sprintf("containarium gateway key set %s --provider %s --key <value>", keyOwnerOrPlaceholder(keyOwner), provider),
	}
}

func keyOwnerOrPlaceholder(keyOwner string) string {
	if keyOwner == "" {
		return "<key-owner>"
	}
	return keyOwner
}

// SkillEngine is the minimal view of a catalog skill Statuses needs: its id
// and its manifest's own engine choice. Deliberately narrower than
// *pb.AgentSkill — Statuses only ever reads these two fields, and a narrow
// input type keeps this package's tests from having to construct a full
// skill (recipe, scopes, agent card, ...) just to exercise grouping.
type SkillEngine struct {
	ID     string
	Engine pb.AgentEngine
}

// Statuses is Resolve applied to every concrete engine, for one key owner —
// the read-only readiness report ListAgentEngines serves (#2223). It never
// errors on a not-ready engine: that IS a row, not a failure. skills groups
// each row's SkillIds: only a skill whose manifest names that engine
// EXPLICITLY (#2222 Q2, decided 2026-10-01) — an unspecified-engine skill is
// never attributed to any row, even the one is_default marks.
func Statuses(ctx context.Context, keyOwner string, gw *Gateway, skills []SkillEngine) []*pb.AgentEngineStatus {
	defaultEngine := pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED
	if gw != nil {
		defaultEngine = ForProvider(gw.DefaultProvider)
	}

	skillIDs := make(map[pb.AgentEngine][]string)
	for _, s := range skills {
		if s.Engine == pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED {
			continue
		}
		skillIDs[s.Engine] = append(skillIDs[s.Engine], s.ID)
	}

	out := make([]*pb.AgentEngineStatus, 0, len(All()))
	for _, e := range All() {
		provider, _ := Provider(e) // ok=false unreachable for a value from All()
		providerEnum, _ := gatewayprovider.FromName(provider)

		row := &pb.AgentEngineStatus{
			Engine:    e,
			Provider:  providerEnum,
			IsDefault: gw != nil && e == defaultEngine,
			SkillIds:  skillIDs[e],
		}

		if gw == nil {
			row.Readiness = pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_UNKNOWN_DIRECT_MODE
			row.Source = pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_DIRECT_MODE
			row.Reason = "daemon serves no model gateway; the box's own secrets decide"
			out = append(out, row)
			continue
		}

		res, err := Resolve(ctx, e, keyOwner, gw)
		if err == nil {
			row.Readiness = pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_READY
			if gw.GlobalProviders[res.Provider] {
				row.Source = pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_GLOBAL_KEY
			} else {
				row.Source = pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_OWNER_KEY
			}
			out = append(out, row)
			continue
		}

		row.Readiness = pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_NOT_READY
		var notReady *NotReadyError
		if errors.As(err, &notReady) {
			row.Reason = notReady.Reason + "; fix: " + notReady.Fix
		} else {
			row.Reason = err.Error()
		}
		out = append(out, row)
	}
	return out
}
