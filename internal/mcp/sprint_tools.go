package mcp

import (
	"fmt"
	"strings"
)

// sprintTools is the MCP catalog for reading the sprint board a hosted
// control plane mirrors onto each sprint umbrella issue. Both tools are
// read-only and hit routes that exist only on a hosted control plane; against
// a standalone daemon they return that daemon's plain not-found error.
//
// A sprint has no id: it is addressed by its umbrella issue (provider,
// project, number).
func sprintTools() []Tool {
	orgProp := map[string]interface{}{"type": "string", "description": "Organization id."}
	return []Tool{
		{
			Name: "sprint_board",
			Description: "Read the sprint board mirrored on one umbrella issue: the items, their " +
				"rank, state, blockers, runs and pull requests. Returns the board as rendered " +
				"markdown. NO_MIRROR_YET (the board has not been written yet), NOT_ENABLED " +
				"(the repository has not opted in) and PROVIDER_NOT_SUPPORTED are normal " +
				"results, not errors; a REJECTED mirror (failed verification) is an error. " +
				"Never computes a board live.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"org_id":  orgProp,
					"project": map[string]interface{}{"type": "string", "description": "Repository of the umbrella issue, e.g. \"owner/repo\"."},
					"number":  map[string]interface{}{"type": "integer", "description": "Umbrella issue number."},
					"provider": map[string]interface{}{
						"type":        "string",
						"description": "Tracker provider of the umbrella: \"github\" (default) or \"gitlab\".",
					},
				},
				"required": []string{"org_id", "project", "number"},
			},
			Handler: handleSprintBoard,
		},
		{
			Name: "sprint_list",
			Description: "List the organization's sprints (open issues labelled \"sprint\" on " +
				"repositories that opted in) with each one's mirror state. Use sprint_board " +
				"to read a board.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{"org_id": orgProp},
				"required":   []string{"org_id"},
			},
			Handler: handleSprintList,
		},
	}
}

func parseSprintProvider(s string) (TrackerProvider, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "github":
		return TrackerProviderGitHub, nil
	case "gitlab":
		return TrackerProviderGitLab, nil
	}
	return "", fmt.Errorf("provider must be \"github\" or \"gitlab\", got %q", s)
}

func sprintStateWord(s SprintMirrorState) string {
	return strings.TrimPrefix(string(s), "SPRINT_MIRROR_STATE_")
}

func handleSprintBoard(client API, args map[string]interface{}) (string, error) {
	org := getStringArg(args, "org_id", "")
	project := getStringArg(args, "project", "")
	number, ok := getInt64Arg(args, "number")
	if org == "" || project == "" || !ok || number <= 0 {
		return "", fmt.Errorf("org_id, project and a positive number are required")
	}
	provider, err := parseSprintProvider(getStringArg(args, "provider", ""))
	if err != nil {
		return "", err
	}
	m, err := client.GetSprintBoard(GetSprintBoardRequest{OrgID: org, Provider: provider, Project: project, Number: number})
	if err != nil {
		return "", err
	}
	ref := fmt.Sprintf("%s#%d", project, number)
	switch m.State {
	case SprintMirrorStatePresent:
		var b strings.Builder
		fmt.Fprintf(&b, "Sprint board %s (state: PRESENT)", ref)
		if m.Board != nil {
			fmt.Fprintf(&b, ", %d items", len(m.Board.Items))
			if m.Board.Partial {
				fmt.Fprintf(&b, ", partial: %s", m.Board.PartialReason)
			}
			if m.Board.AsOf != "" {
				fmt.Fprintf(&b, ", as of %s", m.Board.AsOf)
			}
		}
		b.WriteString("\n\n")
		b.WriteString(m.RenderedMarkdown)
		return b.String(), nil
	case SprintMirrorStateNoMirrorYet:
		return fmt.Sprintf("%s: state NO_MIRROR_YET: no board yet (it has not been written for this sprint).", ref), nil
	case SprintMirrorStateNotEnabled:
		return fmt.Sprintf("%s: state NOT_ENABLED: the sprint board is not enabled for this repository.", ref), nil
	case SprintMirrorStateProviderNotSupported:
		return fmt.Sprintf("%s: state PROVIDER_NOT_SUPPORTED: reading sprint boards is not supported yet for this tracker.", ref), nil
	case SprintMirrorStateRejected:
		return "", fmt.Errorf("%s: sprint mirror REJECTED: the mirror comment failed verification and was not returned", ref)
	default:
		return "", fmt.Errorf("%s: unexpected sprint mirror state %q", ref, m.State)
	}
}

func handleSprintList(client API, args map[string]interface{}) (string, error) {
	org := getStringArg(args, "org_id", "")
	if org == "" {
		return "", fmt.Errorf("org_id is required")
	}
	sprints, err := client.ListSprints(ListSprintsRequest{OrgID: org})
	if err != nil {
		return "", err
	}
	if len(sprints) == 0 {
		return "No sprints found (a sprint is an open issue labelled \"sprint\" on a repository that opted in).", nil
	}
	var b strings.Builder
	for _, s := range sprints {
		fmt.Fprintf(&b, "%s#%d  %s  [%s]\n", s.Umbrella.Project, s.Umbrella.Number, s.Title, sprintStateWord(s.State))
	}
	return b.String(), nil
}
