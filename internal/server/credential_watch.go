package server

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
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

var credentialEpisodeID = regexp.MustCompile(`^[a-f0-9-]{36}$`)

// Runtime state is a private protocol, independent of the public status RPC.
func (s *AgentSkillServer) CredentialEpisodes(_ context.Context, t alert.CredentialWatchTarget) (alert.CredentialEpisodes, error) {
	var result alert.CredentialEpisodes
	if t.Engine != pb.AgentEngine_AGENT_ENGINE_CLAUDE {
		return result, nil
	}
	out, _, code, err := s.recipes.containers.manager.ExecWithExitCode(t.Box, []string{"sh", "-c", `if command -v agent-runtime-credential-state >/dev/null 2>&1; then exec agent-runtime-credential-state snapshot; else echo '{"version":1,"active":false,"pending":[]}'; fi`})
	if err != nil || code != 0 {
		return result, fmt.Errorf("credential runtime state unavailable")
	}
	if len(out) > 1<<20 || json.Unmarshal([]byte(out), &result) != nil || result.Version != 1 || len(result.Pending) > 256 {
		return result, fmt.Errorf("invalid credential runtime observation")
	}
	for _, e := range result.Pending {
		if !credentialEpisodeID.MatchString(e.ID) {
			return result, fmt.Errorf("invalid credential episode ID")
		}
	}
	return result, nil
}
func (s *AgentSkillServer) AcknowledgeCredentialEpisodes(_ context.Context, t alert.CredentialWatchTarget, ids []string) error {
	if len(ids) > 256 {
		return fmt.Errorf("too many credential episodes")
	}
	args := []string{"agent-runtime-credential-state", "ack"}
	for _, id := range ids {
		if !credentialEpisodeID.MatchString(id) {
			return fmt.Errorf("invalid credential episode ID")
		}
		args = append(args, id)
	}
	_, _, code, err := s.recipes.containers.manager.ExecWithExitCode(t.Box, args)
	if err != nil || code != 0 {
		return fmt.Errorf("credential runtime acknowledgement unavailable")
	}
	return nil
}
