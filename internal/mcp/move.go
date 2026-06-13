package mcp

import (
	"encoding/json"
	"fmt"
)

// handleMoveContainer is the MCP tool handler for `move_container`.
// Thin wrapper over the daemon's POST /v1/containers/{username}/move —
// the actual orchestration (snapshot, pre-copy, cutover, route swap)
// runs daemon-side. The MCP server just relays the call and renders
// the response in a human-readable shape that the agent can show
// directly to the operator.
func handleMoveContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}
	target, ok := args["target_backend_id"].(string)
	if !ok || target == "" {
		return "", fmt.Errorf("target_backend_id is required")
	}

	body := map[string]interface{}{
		"username":          username,
		"target_backend_id": target,
	}
	// Optional knobs — pass them through if set so the daemon's
	// migrationDefaults() applies its own clamping. JSON numbers
	// arrive as float64; convert to int32 for the daemon's request.
	if v, ok := args["max_iterations"].(float64); ok {
		body["max_iterations"] = int32(v)
	}
	if v, ok := args["delta_threshold_seconds"].(float64); ok {
		body["delta_threshold_seconds"] = int32(v)
	}
	if v, ok := args["stateful"].(bool); ok {
		body["stateful"] = v
	}

	respBody, err := client.doRequest("POST",
		fmt.Sprintf("/v1/containers/%s/move", username), body)
	if err != nil {
		return "", fmt.Errorf("call move RPC: %w", err)
	}

	var parsed struct {
		Message         string `json:"message"`
		NewIPAddress    string `json:"newIpAddress"`
		TargetBackendID string `json:"targetBackendId"`
		IterationsRun   int32  `json:"iterationsRun"`
		DowntimeSeconds int32  `json:"downtimeSeconds"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	out := fmt.Sprintf("✅ %s\n\n", parsed.Message)
	out += fmt.Sprintf("Target backend:   %s\n", parsed.TargetBackendID)
	out += fmt.Sprintf("New container IP: %s\n", parsed.NewIPAddress)
	out += fmt.Sprintf("Iterations run:   %d\n", parsed.IterationsRun)
	out += fmt.Sprintf("Cutover downtime: %ds\n", parsed.DowntimeSeconds)
	out += "\nThe public hostname is unchanged. The route store " +
		"target_ip swap propagates to Caddy via RouteSyncJob within " +
		"~5 seconds; sshpiper keysync picks up the destination's new " +
		"host user within ~2 minutes."
	return out, nil
}
