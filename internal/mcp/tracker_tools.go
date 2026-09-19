package mcp

import (
	"fmt"
	"strings"
)

// trackerTools is the MCP-side catalog for the tracker broker's
// agent-facing verbs (#1922 step 7). Pulled into tools.go's registration
// list via trackerTools(), mirroring kmsTools()/backupTools().
//
// Deliberately six tools, not the design note's illustrative "seven":
// connection CRUD and GetTrackerStatus are all tracker:admin — an
// operator concern, surfaced via `containarium tracker connect/status`
// — never something an agent's run-scoped JWT (tracker:read/write) can
// reach, the same reasoning that keeps container/secret admin ops off
// the agent-facing tool set entirely.
//
// Every tool is a thin wrapper over the same REST endpoints
// `containarium tracker issue ...` / `tracker change ...` call (the
// generated TrackerService gateway) — per CLAUDE.md's CLI-first rule.
func trackerTools() []Tool {
	return []Tool{
		{
			Name: "tracker_get_issue",
			Description: "Read a single tracker issue, including its comments, from the tracker " +
				"connection this run is bound to (or any connection in your tenant, for an " +
				"operator token). Mirrors `containarium tracker issue view`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":   map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection": map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"number":     map[string]interface{}{"type": "integer", "description": "Issue number."},
				},
				"required": []string{"username", "connection", "number"},
			},
			Handler: handleTrackerGetIssue,
		},
		{
			Name: "tracker_list_issues",
			Description: "List tracker issues, optionally filtered by state, labels (AND), or " +
				"free-text search. Never includes comments — use tracker_get_issue for a single " +
				"issue's comments. Mirrors `containarium tracker issue list`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":   map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection": map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"state": map[string]interface{}{
						"type":        "string",
						"description": "Filter by state: \"open\" or \"closed\". Omit for any state.",
					},
					"labels": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Require ALL of these labels present.",
					},
					"search": map[string]interface{}{
						"type":        "string",
						"description": "Free-text query against title/body, passed through to the provider's own search.",
					},
				},
				"required": []string{"username", "connection"},
			},
			Handler: handleTrackerListIssues,
		},
		{
			Name: "tracker_get_change",
			Description: "Read a single change request's (pull/merge request) state and " +
				"normalized CI verdict. Mirrors `containarium tracker change view`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":   map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection": map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"number":     map[string]interface{}{"type": "integer", "description": "Change (pull/merge request) number."},
				},
				"required": []string{"username", "connection", "number"},
			},
			Handler: handleTrackerGetChange,
		},
		{
			Name: "tracker_comment",
			Description: "Post a comment on a tracker issue or change request, stamped with this " +
				"run's platform identity and sanitized against forged markers and GitLab " +
				"quick-actions server-side. Mirrors `containarium tracker issue comment`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":   map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection": map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"number":     map[string]interface{}{"type": "integer", "description": "Issue or change number."},
					"body":       map[string]interface{}{"type": "string", "description": "Comment text."},
				},
				"required": []string{"username", "connection", "number", "body"},
			},
			Handler: handleTrackerComment,
		},
		{
			Name: "tracker_claim",
			Description: "Claim a tracker issue for this run: posts a stamped claim comment and " +
				"assigns this run's identity if the issue is unassigned, unless a live or recent " +
				"claim from a different run already holds it. Idempotent for the same run. " +
				"Mirrors `containarium tracker issue claim`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":   map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection": map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"number":     map[string]interface{}{"type": "integer", "description": "Issue number."},
					"stale_after_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "How long a claim from an unconfirmed run is still honored before being takeable. Omit for the daemon's default (2 hours).",
					},
				},
				"required": []string{"username", "connection", "number"},
			},
			Handler: handleTrackerClaim,
		},
		{
			Name:        "tracker_set_labels",
			Description: "Add and/or remove labels on a tracker issue. Mirrors `containarium tracker issue label`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":      map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection":    map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"number":        map[string]interface{}{"type": "integer", "description": "Issue number."},
					"add_labels":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Labels to add."},
					"remove_labels": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Labels to remove."},
				},
				"required": []string{"username", "connection", "number"},
			},
			Handler: handleTrackerSetLabels,
		},
	}
}

func handleTrackerGetIssue(client API, args map[string]interface{}) (string, error) {
	number, _ := getInt64Arg(args, "number")
	issue, err := client.GetTrackerIssue(GetTrackerIssueRequest{
		Username:   getStringArg(args, "username", ""),
		Connection: getStringArg(args, "connection", ""),
		Number:     number,
	})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#%d %s [%s]\n", issue.Number, issue.Title, issue.State)
	if issue.Assignee != "" {
		fmt.Fprintf(&b, "Assignee: %s\n", issue.Assignee)
	}
	if len(issue.Labels) > 0 {
		fmt.Fprintf(&b, "Labels: %s\n", strings.Join(issue.Labels, ", "))
	}
	fmt.Fprintf(&b, "\n%s\n", issue.Body)
	for _, c := range issue.Comments {
		fmt.Fprintf(&b, "\n--- %s (%s) ---\n%s\n", c.Author, c.CreatedAt, c.Body)
	}
	return b.String(), nil
}

func handleTrackerListIssues(client API, args map[string]interface{}) (string, error) {
	issues, err := client.ListTrackerIssues(ListTrackerIssuesRequest{
		Username:   getStringArg(args, "username", ""),
		Connection: getStringArg(args, "connection", ""),
		State:      getStringArg(args, "state", ""),
		Labels:     getStringSliceArg(args, "labels"),
		Search:     getStringArg(args, "search", ""),
	})
	if err != nil {
		return "", err
	}
	if len(issues) == 0 {
		return "No issues match.", nil
	}
	var b strings.Builder
	for _, issue := range issues {
		fmt.Fprintf(&b, "#%d %s [%s]", issue.Number, issue.Title, issue.State)
		if issue.Assignee != "" {
			fmt.Fprintf(&b, " (assignee: %s)", issue.Assignee)
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func handleTrackerGetChange(client API, args map[string]interface{}) (string, error) {
	number, _ := getInt64Arg(args, "number")
	change, err := client.GetTrackerChange(GetTrackerChangeRequest{
		Username:   getStringArg(args, "username", ""),
		Connection: getStringArg(args, "connection", ""),
		Number:     number,
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("#%d [%s] CI: %s\n%s", change.Number, change.State, change.CiVerdict, change.Url), nil
}

func handleTrackerComment(client API, args map[string]interface{}) (string, error) {
	number, _ := getInt64Arg(args, "number")
	comment, err := client.CommentOnTrackerIssue(CommentOnTrackerIssueRequest{
		Username:   getStringArg(args, "username", ""),
		Connection: getStringArg(args, "connection", ""),
		Number:     number,
		Body:       getStringArg(args, "body", ""),
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Comment posted by %s.", comment.Author), nil
}

func handleTrackerClaim(client API, args map[string]interface{}) (string, error) {
	number, _ := getInt64Arg(args, "number")
	staleAfter, _ := getInt64Arg(args, "stale_after_seconds")
	result, err := client.ClaimTrackerIssue(ClaimTrackerIssueRequest{
		Username:          getStringArg(args, "username", ""),
		Connection:        getStringArg(args, "connection", ""),
		Number:            number,
		StaleAfterSeconds: staleAfter,
	})
	if err != nil {
		return "", err
	}
	if result.Claimed {
		if result.Assigned {
			return "Claimed and assigned.", nil
		}
		return "Claimed (issue already had an assignee).", nil
	}
	return fmt.Sprintf("Not claimed — already held by run %s.", result.AlreadyClaimedByRunID), nil
}

func handleTrackerSetLabels(client API, args map[string]interface{}) (string, error) {
	number, _ := getInt64Arg(args, "number")
	err := client.SetTrackerIssueLabels(SetTrackerIssueLabelsRequest{
		Username:     getStringArg(args, "username", ""),
		Connection:   getStringArg(args, "connection", ""),
		Number:       number,
		AddLabels:    getStringSliceArg(args, "add_labels"),
		RemoveLabels: getStringSliceArg(args, "remove_labels"),
	})
	if err != nil {
		return "", err
	}
	return "Labels updated.", nil
}
