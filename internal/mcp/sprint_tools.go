package mcp

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
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

func handleSprintBoard(api API, args map[string]interface{}) (string, error) {
	org := getStringArg(args, "org_id", "")
	project := getStringArg(args, "project", "")
	number, ok := getInt64Arg(args, "number")
	if org == "" || project == "" || !ok || number <= 0 {
		return "", fmt.Errorf("org_id, project and a positive number are required")
	}
	provider, err := client.ParseSprintProvider(getStringArg(args, "provider", ""))
	if err != nil {
		return "", err
	}
	m, err := api.GetSprintBoard(GetSprintBoardRequest{OrgID: org, Provider: provider, Project: project, Number: number})
	if err != nil {
		return "", err
	}
	return client.FormatSprintBoard(project, number, m)
}

func handleSprintList(api API, args map[string]interface{}) (string, error) {
	org := getStringArg(args, "org_id", "")
	if org == "" {
		return "", fmt.Errorf("org_id is required")
	}
	sprints, err := api.ListSprints(ListSprintsRequest{OrgID: org})
	if err != nil {
		return "", err
	}
	return client.FormatSprintList(sprints), nil
}
