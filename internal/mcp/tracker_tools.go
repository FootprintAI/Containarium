package mcp

import (
	"fmt"
	"strings"
)

// trackerTools is the MCP-side catalog for the tracker broker's
// agent-facing verbs (#1922 step 7, #1923's SubmitTrackerChange added
// here rather than a separate catalog). Pulled into tools.go's
// registration list via trackerTools(), mirroring kmsTools()/backupTools().
//
// Seven tools, matching the design note's own verb count exactly:
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
		{
			Name: "tracker_submit_change",
			Description: "Bundle this run's committed workspace out of its box, push it from a " +
				"fresh temporary bare repository on the host to a daemon-chosen branch, and open " +
				"a change request referencing the given issue — no push credential ever enters " +
				"the box. Requires this run to have a recorded git_source. Mirrors " +
				"`containarium tracker change submit`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":    map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection":  map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"issue":       map[string]interface{}{"type": "integer", "description": "Issue this change closes/references."},
					"title":       map[string]interface{}{"type": "string", "description": "Change request title."},
					"description": map[string]interface{}{"type": "string", "description": "Change request description."},
					"draft":       map[string]interface{}{"type": "boolean", "description": "Open as a draft/WIP."},
				},
				"required": []string{"username", "connection", "issue", "title"},
			},
			Handler: handleTrackerSubmitChange,
		},
		{
			Name: "tracker_route_list",
			Description: "List a tracker connection's scope routes: which agent skill each " +
				"scope:<role> label starts. Requires tracker:admin. Mirrors " +
				"`containarium tracker route list`; route writes are CLI-only " +
				"(`containarium tracker route set|delete`).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":   map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection": map[string]interface{}{"type": "string", "description": "Tracker connection name."},
				},
				"required": []string{"username", "connection"},
			},
			Handler: handleTrackerRouteList,
		},
		{
			Name: "tracker_create_issue",
			Description: "File a follow-up issue on the tracker connection this run is bound to (#2024). " +
				"Labels must pass the connection's allow-list (scope:*, model:*, agent:needs-approval by default); " +
				"anything else is rejected before the tracker is touched. A run must name parent_number: the " +
				"follow-up is linked to its parent, filed with agent:needs-approval unless the connection " +
				"auto-chains, stamped with this run's identity, and bounded by the connection's depth and " +
				"fan-out caps. Mirrors `containarium tracker issue create`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username":   map[string]interface{}{"type": "string", "description": "Tenant username."},
					"connection": map[string]interface{}{"type": "string", "description": "Tracker connection name."},
					"title":      map[string]interface{}{"type": "string", "description": "Issue title."},
					"body":       map[string]interface{}{"type": "string", "description": "Issue body. The parent link and identity stamp are appended server-side."},
					"labels": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Labels to apply; each must pass the connection's allow-list.",
					},
					"parent_number": map[string]interface{}{"type": "integer", "description": "Parent issue number. Required for a run-scoped token."},
				},
				"required": []string{"username", "connection", "title"},
			},
			Handler: handleTrackerCreateIssue,
		},
	}
}

func handleTrackerRouteList(client API, args map[string]interface{}) (string, error) {
	routes, err := client.ListTrackerRoutes(ListTrackerRoutesRequest{
		Username:   getStringArg(args, "username", ""),
		Connection: getStringArg(args, "connection", ""),
	})
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "No scope routes on this connection; scope:* labels will not start any run.", nil
	}
	var b strings.Builder
	for _, r := range routes {
		fmt.Fprintf(&b, "scope:%s -> %s\n", r.Scope, r.SkillID)
	}
	return b.String(), nil
}

func handleTrackerCreateIssue(client API, args map[string]interface{}) (string, error) {
	parent, _ := getInt64Arg(args, "parent_number")
	issue, err := client.CreateTrackerIssue(CreateTrackerIssueRequest{
		Username:     getStringArg(args, "username", ""),
		Connection:   getStringArg(args, "connection", ""),
		Title:        getStringArg(args, "title", ""),
		Body:         getStringArg(args, "body", ""),
		Labels:       getStringSliceArg(args, "labels"),
		ParentNumber: parent,
	})
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Created #%d %s", issue.Number, issue.Title)
	if len(issue.Labels) > 0 {
		msg += fmt.Sprintf(" [%s]", strings.Join(issue.Labels, ", "))
	}
	return msg + ".", nil
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

func handleTrackerSubmitChange(client API, args map[string]interface{}) (string, error) {
	issue, _ := getInt64Arg(args, "issue")
	change, err := client.SubmitTrackerChange(SubmitTrackerChangeRequest{
		Username:    getStringArg(args, "username", ""),
		Connection:  getStringArg(args, "connection", ""),
		Issue:       issue,
		Title:       getStringArg(args, "title", ""),
		Description: getStringArg(args, "description", ""),
		Draft:       getBoolArg(args, "draft", false),
	})
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("#%d opened on branch %s.", change.Number, change.Branch)
	if change.Url != "" {
		msg += fmt.Sprintf(" %s", change.Url)
	}
	return msg, nil
}
