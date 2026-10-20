package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/coderun/engine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// AgentSkillServer is the credential-expiry watcher's CredentialProber
// (#2371): it lists the skill boxes worth probing and probes one through the
// watcher policy probe; the manual RPC continues to show raw token expiry.

// CredentialWatchTargets lists every running skill box whose skill is in the
// catalog and whose engine has a credential-status probe. A stopped box is
// skipped (it cannot be exec'd into) and is picked up again once it runs.
func (s *AgentSkillServer) CredentialWatchTargets(context.Context) ([]alert.CredentialWatchTarget, error) {
	if s.recipes == nil || s.recipes.containers == nil || s.recipes.containers.manager == nil {
		return nil, nil
	}
	list, err := s.recipes.containers.manager.List()
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	var targets []alert.CredentialWatchTarget
	for _, c := range list {
		if c.State != "Running" || !strings.HasPrefix(c.Name, agentBoxPrefix) || !strings.HasSuffix(c.Name, "-container") {
			continue
		}
		skillID := strings.TrimSuffix(strings.TrimPrefix(c.Name, agentBoxPrefix), "-container")
		skill, gerr := s.catalog.Get(skillID)
		if gerr != nil {
			continue // a box whose skill left the catalog is not ours to probe
		}
		if _, resolved, ok := codeEngineFor(skill.GetEngine()); ok {
			targets = append(targets, alert.CredentialWatchTarget{SkillID: skill.Id, Box: c.Name, Engine: resolved})
		}
	}
	return targets, nil
}

// ProbeCredential runs the target engine's credential-status probe in the
// target box with the #2790 alert policy. Names only — see probeBoxCredential.
func (s *AgentSkillServer) ProbeCredential(_ context.Context, t alert.CredentialWatchTarget) (pb.CodeCredentialSource, error) {
	engineName, _, ok := codeEngineFor(t.Engine)
	if !ok {
		return pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_UNSPECIFIED,
			fmt.Errorf("no credential-status probe for engine %s", t.Engine)
	}
	script, _ := engine.CredentialAlertStatusScript(engineName)
	return s.probeBoxCredentialScript(t.Box, script)
}
