package mcp

import (
	"fmt"
	"net/url"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// sshKeysTools (#2945): a thin wrapper over PUT /v1/containers/{username}/ssh-keys
// (SetSSHKeys), the call `containarium ssh-keys set` also makes.
func sshKeysTools() []Tool {
	return []Tool{
		{
			Name: "set_ssh_keys",
			Description: "Replace a box user's authorized SSH keys with exactly the given list. " +
				"Keys not in the list are removed and revoked registry-wide: the key is revoked for every account holding it, including the same user's other boxes where it remains in the file. Keys the platform manages itself " +
				"are always kept. Idempotent. Every key must be a single-line public key with no " +
				"options (command=, from=); one invalid key fails the whole call with no change. " +
				"An empty list removes every caller-managed key and needs allow_empty=true. " +
				"Same access as adding a key.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Username of the box"},
					"ssh_public_keys": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "The complete desired list of public keys",
					},
					"allow_empty": map[string]interface{}{
						"type":        "boolean",
						"description": "Must be true to send an empty list (removes every caller-managed key)",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleSetSSHKeys,
		},
	}
}

func handleSetSSHKeys(client API, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	req := &pb.SetSSHKeysRequest{Username: username, AllowEmpty: getBoolArg(args, "allow_empty", false)}
	if raw, ok := args["ssh_public_keys"].([]interface{}); ok {
		for _, v := range raw {
			k, ok := v.(string)
			if !ok {
				return "", fmt.Errorf("ssh_public_keys must be an array of strings")
			}
			req.SshPublicKeys = append(req.SshPublicKeys, k)
		}
	}
	body, err := protojson.Marshal(req)
	if err != nil {
		return "", err
	}
	respBody, err := client.doRequest("PUT", "/v1/containers/"+url.PathEscape(username)+"/ssh-keys", body)
	if err != nil {
		return "", fmt.Errorf("failed to set ssh keys: %w", err)
	}
	var resp pb.SetSSHKeysResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return fmt.Sprintf("✅ %s (removed %d, %d caller-managed key(s) now authorized)", resp.Message, resp.RemovedKeys, resp.TotalKeys), nil
}
