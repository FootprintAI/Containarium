package mcp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/gatewayprovider"
)

// Model-gateway mint, over the generated ModelGatewayService REST gateway
// (#1726). Same endpoint `containarium gateway mint` calls.

// MintGatewayTokenBody is the tool-facing request. Provider and TTL are taken in
// the shapes a human or an agent actually types — a lowercase provider name and a
// Go duration — and translated here into the wire shapes protojson requires (the
// enum's value NAME, and a seconds-suffixed Duration). Doing that translation in
// one place is why the tool handler stays free of protojson trivia.
type MintGatewayTokenBody struct {
	Box           string
	Provider      string
	RunID         string
	TTL           string
	AllowedModels []string
	DryRun        bool
}

// mintGatewayTokenWire is the protojson body of MintGatewayTokenRequest.
type mintGatewayTokenWire struct {
	Box           string   `json:"box"`
	Provider      string   `json:"provider"`
	RunID         string   `json:"runId,omitempty"`
	AllowedModels []string `json:"allowedModels,omitempty"`
	TTL           string   `json:"ttl,omitempty"`
	DryRun        bool     `json:"dryRun,omitempty"`
}

// MintGatewayTokenResponse is the minted token and where to point at it. Token
// and TokenID are empty on a dry run.
type MintGatewayTokenResponse struct {
	Token     string `json:"token"`
	BaseURL   string `json:"baseUrl"`
	KeyOwner  string `json:"keyOwner"`
	ExpiresAt string `json:"expiresAt"`
	TokenID   string `json:"tokenId"`
}

// MintGatewayToken mints a scoped gateway token for a box the caller owns.
func (c *Client) MintGatewayToken(req MintGatewayTokenBody) (*MintGatewayTokenResponse, error) {
	wire, err := req.toWire()
	if err != nil {
		return nil, err
	}
	respBody, err := c.doRequest("POST", "/v1/model-gateway/tokens", wire)
	if err != nil {
		return nil, err
	}
	var resp MintGatewayTokenResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// toWire validates and converts the tool-facing request into its protojson form.
func (b MintGatewayTokenBody) toWire() (mintGatewayTokenWire, error) {
	p, err := gatewayprovider.FromName(b.Provider)
	if err != nil {
		return mintGatewayTokenWire{}, err
	}
	out := mintGatewayTokenWire{
		// The enum's value NAME, not the lowercase registry name: protojson
		// decodes an enum from its name, and the daemon maps it back. Sending
		// "kafeido" here would be rejected at the gateway, not at the handler.
		Box:           b.Box,
		Provider:      p.String(),
		RunID:         b.RunID,
		AllowedModels: b.AllowedModels,
		DryRun:        b.DryRun,
	}
	if b.TTL != "" {
		d, perr := time.ParseDuration(b.TTL)
		if perr != nil {
			return mintGatewayTokenWire{}, fmt.Errorf("ttl %q is not a duration (e.g. 30m, 2h): %w", b.TTL, perr)
		}
		if d <= 0 {
			return mintGatewayTokenWire{}, fmt.Errorf("ttl must be positive, got %s", b.TTL)
		}
		// protojson's Duration form: seconds with an "s" suffix. A Go duration
		// string ("2h") is NOT valid protojson and would fail to decode.
		out.TTL = fmt.Sprintf("%ss", trimFloat(d.Seconds()))
	}
	return out, nil
}

// trimFloat renders a seconds count without a trailing ".000000".
func trimFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
