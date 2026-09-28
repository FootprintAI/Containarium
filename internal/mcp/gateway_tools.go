package mcp

import (
	"fmt"
	"strings"
)

// gatewayTools is the MCP-side catalog for the model gateway's mint surface
// (#1726). Pulled into tools.go's registration list via gatewayTools(),
// mirroring kmsTools().
//
// Per CLAUDE.md's CLI-first rule this is a THIN wrapper: one tool, over the same
// ModelGatewayService.MintGatewayToken RPC `containarium gateway mint` calls. It
// adds no capability the shell does not already have.
//
// Deliberately absent: the key verbs. Registering or removing a key owner's REAL
// upstream provider key is an operator/control-plane action gated by
// gateway:admin, and an agent has no business holding a credential it could spend
// as somebody else. An agent minting a scoped, expiring token for its own box is
// the whole point; an agent writing the key that token draws on is not.
func gatewayTools() []Tool {
	return []Tool{
		{
			Name: "mint_gateway_token",
			Description: "Mint a short-lived, scoped model-gateway token for a box " +
				"you own, so an engine in that box can call models without ever " +
				"holding a real provider key. The token is bound to the box, the " +
				"provider, the resolved key owner (the box's cloud-org attribution " +
				"when stamped, else its owning username) and optionally one run and " +
				"a model ceiling; its TTL is capped server-side and it can be revoked " +
				"by its token_id before expiry. Use dry_run to check that a mint " +
				"WOULD succeed without issuing anything. Mirrors " +
				"`containarium gateway mint`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"box": map[string]interface{}{
						"type":        "string",
						"description": "The box to mint for, as its tenant username or <username>-container. Must be a box you own.",
					},
					"provider": map[string]interface{}{
						"type":        "string",
						"description": "Upstream provider name, e.g. anthropic, openai, gemini, gemini-openai, kafeido.",
					},
					"run_id": map[string]interface{}{
						"type":        "string",
						"description": "Optional. Binds the token to one run, so the run's exit can revoke exactly this token.",
					},
					"ttl": map[string]interface{}{
						"type":        "string",
						"description": "Optional requested lifetime as a Go duration (e.g. 30m, 2h). Capped server-side; omitted takes the default.",
					},
					"allowed_models": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional ceiling: the gateway refuses any model not in this list.",
					},
					"dry_run": map[string]interface{}{
						"type":        "boolean",
						"description": "Validate everything a real mint validates and issue NO token. Default false.",
					},
				},
				"required": []string{"box", "provider"},
			},
			Handler: handleMintGatewayToken,
		},
	}
}

func handleMintGatewayToken(client API, args map[string]interface{}) (string, error) {
	box := getStringArg(args, "box", "")
	if box == "" {
		return "", fmt.Errorf("box is required")
	}
	provider := getStringArg(args, "provider", "")
	if provider == "" {
		return "", fmt.Errorf("provider is required")
	}
	req := MintGatewayTokenBody{
		Box:           box,
		Provider:      provider,
		RunID:         getStringArg(args, "run_id", ""),
		TTL:           getStringArg(args, "ttl", ""),
		AllowedModels: getStringSliceArg(args, "allowed_models"),
		DryRun:        getBoolArg(args, "dry_run", false),
	}
	resp, err := client.MintGatewayToken(req)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	if req.DryRun {
		// A dry run issued nothing, so this must not print a token field at all —
		// an empty "token:" line invites a caller to use it.
		fmt.Fprintf(&b, "A mint would succeed (dry run — no token issued).\n")
		fmt.Fprintf(&b, "key_owner: %s\n", resp.KeyOwner)
		fmt.Fprintf(&b, "base_url:  %s\n", resp.BaseURL)
		return b.String(), nil
	}
	fmt.Fprintf(&b, "token:      %s\n", resp.Token)
	fmt.Fprintf(&b, "base_url:   %s\n", resp.BaseURL)
	fmt.Fprintf(&b, "key_owner:  %s\n", resp.KeyOwner)
	fmt.Fprintf(&b, "token_id:   %s\n", resp.TokenID)
	if resp.ExpiresAt != "" {
		fmt.Fprintf(&b, "expires_at: %s\n", resp.ExpiresAt)
	}
	return b.String(), nil
}
