package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const processPolicyPath = "/v1/security/process-policy"

// processPolicyTools (#2666): get / set / release over the process-policy
// REST routes that `containarium security process-policy get|set|release`
// (#2636) calls. Thin wrappers: the same endpoints, the generated protobuf
// request/response types, and the action as the proto enum (validated here, so
// free text is never sent). The mining-behavior thresholds stay CLI-only.
func processPolicyTools() []Tool {
	return []Tool{
		{
			Name: "security_process_policy_get",
			Description: "Show what a HIGH mining finding does to its container: the stored process " +
				"policy and the effective policy the responder applies (action ALERT, THROTTLE or " +
				"FREEZE, throttle allowance, TTL backstop). Without `container` reads the backend " +
				"default; with `container` reads that container's override (none stored means it " +
				"inherits the default). Read-only. Mirrors `containarium security process-policy get`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"container": map[string]interface{}{
						"type":        "string",
						"description": "Container whose override to read; omit for the backend default.",
					},
				},
			},
			Handler: handleSecurityProcessPolicyGet,
		},
		{
			Name: "security_process_policy_set",
			Description: "Set what a HIGH mining finding does to its container. Without `container` " +
				"this writes the backend default; WITH `container` it writes an override for that " +
				"container only (`clear_override` removes it). `action` is ALERT (record and notify " +
				"only), THROTTLE (cap CPU to `throttle_allowance`) or FREEZE (pause the container); " +
				"THROTTLE and FREEZE are reversible with security_process_policy_release and are " +
				"released automatically after `ttl`. Omitted fields inherit. Admin-only. Mirrors " +
				"`containarium security process-policy set` (mining-behavior thresholds are CLI-only). `kill_process` also kills the matched miner process on a miner-signature finding; omit it to inherit.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"action": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"ALERT", "THROTTLE", "FREEZE"},
						"description": "What a HIGH mining finding does to the container.",
					},
					"throttle_allowance": map[string]interface{}{
						"type":        "string",
						"description": "limits.cpu.allowance applied by THROTTLE: \"10%\" or \"10ms/100ms\".",
					},
					"ttl": map[string]interface{}{
						"type":        "string",
						"description": "How long an unreleased action stays before the TTL backstop releases it, e.g. \"24h\".",
					},
					"kill_process": map[string]interface{}{
						"type":        "boolean",
						"description": "Also kill the matched miner process on a HIGH miner-signature finding. Omit to inherit (an explicit false turns the kill off).",
					},
					"container": map[string]interface{}{
						"type":        "string",
						"description": "Write this container's override instead of the backend default.",
					},
					"clear_override": map[string]interface{}{
						"type":        "boolean",
						"description": "Remove the container's override (requires `container`; cannot be combined with policy fields).",
					},
				},
			},
			Handler: handleSecurityProcessPolicySet,
		},
		{
			Name: "security_process_policy_release",
			Description: "Undo the open throttle or freeze on a container: restores the CPU limit " +
				"recorded when it was throttled, or unfreezes it, marks the action released by the " +
				"operator and resolves its finding. A miner-signature finding shared with another " +
				"box of the tenant that still has an action open or a response queued is kept open " +
				"instead (`finding_kept_open: true`; the result's first line says \"Finding #N kept " +
				"open: another box still has a response\") and is resolved when the last box is " +
				"released. Fails (404) when no action is open on the container. Admin-only. " +
				"Mirrors `containarium security process-policy release`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"container": map[string]interface{}{
						"type":        "string",
						"description": "Container to release.",
					},
				},
				"required": []string{"container"},
			},
			Handler: handleSecurityProcessPolicyRelease,
		},
	}
}

// processPolicySetInput is the typed shape of security_process_policy_set's
// arguments, decoded once at the JSON-RPC boundary.
type processPolicySetInput struct {
	Action            string `json:"action"`
	ThrottleAllowance string `json:"throttle_allowance"`
	TTL               string `json:"ttl"`
	Container         string `json:"container"`
	ClearOverride     bool   `json:"clear_override"`
	// KillProcess is a pointer so "omitted" (inherit) differs from false.
	KillProcess *bool `json:"kill_process"`
}

// parseProcessAction maps the tool's spelling (alert|throttle|freeze, any
// case, with or without the PROCESS_ACTION_ prefix) to the proto enum.
func parseProcessAction(s string) (pb.ProcessAction, error) {
	name := strings.ToUpper(strings.TrimSpace(s))
	name = strings.TrimPrefix(name, "PROCESS_ACTION_")
	switch name {
	case "ALERT":
		return pb.ProcessAction_PROCESS_ACTION_ALERT, nil
	case "THROTTLE":
		return pb.ProcessAction_PROCESS_ACTION_THROTTLE, nil
	case "FREEZE":
		return pb.ProcessAction_PROCESS_ACTION_FREEZE, nil
	}
	return pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED,
		fmt.Errorf("invalid action %q: allowed values are ALERT, THROTTLE, FREEZE", s)
}

// buildSetProcessPolicyRequest validates in and builds the request the CLI's
// `process-policy set` would send.
func buildSetProcessPolicyRequest(in processPolicySetInput) (*pb.SetProcessPolicyRequest, error) {
	req := &pb.SetProcessPolicyRequest{Container: in.Container}
	if in.ClearOverride {
		if in.Container == "" {
			return nil, fmt.Errorf("clear_override requires container (only overrides can be cleared)")
		}
		if in.Action != "" || in.ThrottleAllowance != "" || in.TTL != "" || in.KillProcess != nil {
			return nil, fmt.Errorf("clear_override cannot be combined with policy fields")
		}
		req.ClearOverride = true
		return req, nil
	}
	pol := &pb.ProcessPolicy{}
	set := false
	if in.Action != "" {
		a, err := parseProcessAction(in.Action)
		if err != nil {
			return nil, err
		}
		pol.Action, set = a, true
	}
	if in.ThrottleAllowance != "" {
		pol.ThrottleAllowance, set = in.ThrottleAllowance, true // validated by the daemon
	}
	if in.TTL != "" {
		d, err := time.ParseDuration(in.TTL)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("invalid ttl %q: want a positive duration such as 24h or 5m", in.TTL)
		}
		pol.Ttl, set = durationpb.New(d), true
	}
	if in.KillProcess != nil {
		pol.KillProcess, set = in.KillProcess, true
	}
	if !set {
		return nil, fmt.Errorf("nothing to set: give action, throttle_allowance, ttl, kill_process or clear_override")
	}
	req.Policy = pol
	return req, nil
}

func handleSecurityProcessPolicyGet(client API, args map[string]interface{}) (string, error) {
	resp, err := client.GetProcessPolicy(getStringArg(args, "container", ""))
	if err != nil {
		return "", fmt.Errorf("get process policy: %w", err)
	}
	return marshalProto(resp)
}

func handleSecurityProcessPolicySet(client API, args map[string]interface{}) (string, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}
	var in processPolicySetInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}
	req, err := buildSetProcessPolicyRequest(in)
	if err != nil {
		return "", err
	}
	resp, err := client.SetProcessPolicy(req)
	if err != nil {
		return "", fmt.Errorf("set process policy: %w", err)
	}
	return marshalProto(resp)
}

func handleSecurityProcessPolicyRelease(client API, args map[string]interface{}) (string, error) {
	container := getStringArg(args, "container", "")
	if container == "" {
		return "", fmt.Errorf("container is required")
	}
	resp, err := client.ReleaseProcessAction(container)
	if err != nil {
		return "", fmt.Errorf("release process action: %w", err)
	}
	body, err := marshalProto(resp)
	if err != nil {
		return "", err
	}
	return releasedFindingNote(resp) + "\n" + body, nil
}

// releasedFindingNote is the result's first line: what the release did to
// the finding. A miner-signature finding shared with another box of the
// tenant that still has an action open or a response queued is kept open
// (#2766); otherwise it is resolved. Same wording as the CLI.
func releasedFindingNote(resp *pb.ReleaseProcessActionResponse) string {
	if resp.GetFindingKeptOpen() {
		return fmt.Sprintf("Finding #%d kept open: another box still has a response.", resp.GetFinding().GetId())
	}
	return fmt.Sprintf("Finding #%d resolved.", resp.GetFinding().GetId())
}

func marshalProto(m proto.Message) (string, error) {
	b, err := protojson.MarshalOptions{Multiline: true}.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("marshal response: %w", err)
	}
	return string(b), nil
}

func (c *Client) processPolicyRoundTrip(method, path string, req, out proto.Message) error {
	var body interface{}
	if req != nil {
		b, err := protojson.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		body = b // []byte is passed through as already-encoded JSON
	}
	respBody, err := c.doRequest(method, path, body)
	if err != nil {
		return err
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return nil
}

// GetProcessPolicy reads GET /v1/security/process-policy[?container=].
func (c *Client) GetProcessPolicy(container string) (*pb.GetProcessPolicyResponse, error) {
	path := processPolicyPath
	if container != "" {
		path += "?" + url.Values{"container": {container}}.Encode()
	}
	out := &pb.GetProcessPolicyResponse{}
	if err := c.processPolicyRoundTrip("GET", path, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetProcessPolicy writes PUT /v1/security/process-policy.
func (c *Client) SetProcessPolicy(req *pb.SetProcessPolicyRequest) (*pb.SetProcessPolicyResponse, error) {
	out := &pb.SetProcessPolicyResponse{}
	if err := c.processPolicyRoundTrip("PUT", processPolicyPath, req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReleaseProcessAction posts POST /v1/security/process-policy/release.
func (c *Client) ReleaseProcessAction(container string) (*pb.ReleaseProcessActionResponse, error) {
	out := &pb.ReleaseProcessActionResponse{}
	if err := c.processPolicyRoundTrip("POST", processPolicyPath+"/release", &pb.ReleaseProcessActionRequest{Container: container}, out); err != nil {
		return nil, err
	}
	return out, nil
}
