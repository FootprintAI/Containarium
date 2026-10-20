package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const minerSignaturesPath = "/v1/security/miner-signatures"

// minerSignatureTools (#2763): list / add / remove over the REST routes that
// `containarium security miner-signatures list|add|remove` (#2638) calls.
// Thin wrappers: same endpoints, generated protobuf types, and the kind as
// the proto enum (validated here, so free text is never sent).
func minerSignatureTools() []Tool {
	kindSchema := map[string]interface{}{
		"type":        "string",
		"enum":        []string{"name", "argv", "sha256"},
		"description": "Matcher kind: name (process name), argv (command-line marker) or sha256 (binary digest).",
	}
	patternSchema := func(desc string) map[string]interface{} {
		return map[string]interface{}{"type": "string", "description": desc}
	}
	return []Tool{
		{
			Name: "list_miner_signatures",
			Description: "List the merged miner-signature list the miner rule matches against: the " +
				"baseline shipped with the daemon (`builtin: true`) plus operator-added entries. " +
				"Read-only. Mirrors `containarium security miner-signatures list`.",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler:     handleListMinerSignatures,
		},
		{
			Name: "add_miner_signature",
			Description: "Add an operator entry to the miner-signature list, effective immediately and " +
				"persisted across restarts (no daemon rebuild). Admin-only. Mirrors " +
				"`containarium security miner-signatures add`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"kind":    kindSchema,
					"pattern": patternSchema("The name, argv marker or sha256 digest to match."),
					"label":   patternSchema("Optional human-readable label shown in findings."),
				},
				"required": []string{"kind", "pattern"},
			},
			Handler: handleAddMinerSignature,
		},
		{
			Name: "remove_miner_signature",
			Description: "Remove a previously operator-added miner signature. Baseline entries cannot " +
				"be removed. Admin-only. Mirrors `containarium security miner-signatures remove`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"kind":    kindSchema,
					"pattern": patternSchema("The exact pattern of the entry to remove."),
				},
				"required": []string{"kind", "pattern"},
			},
			Handler: handleRemoveMinerSignature,
		},
	}
}

// minerSignatureInput is the typed shape of the add/remove arguments.
type minerSignatureInput struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Label   string `json:"label"`
}

// parseMinerSignatureKind maps the tool's spelling (name|argv|sha256, any
// case, with or without the MINER_SIGNATURE_KIND_ prefix) to the proto enum.
func parseMinerSignatureKind(s string) (pb.MinerSignatureKind, error) {
	name := strings.ToUpper(strings.TrimSpace(s))
	name = strings.TrimPrefix(name, "MINER_SIGNATURE_KIND_")
	switch name {
	case "NAME":
		return pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, nil
	case "ARGV":
		return pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV, nil
	case "SHA256":
		return pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256, nil
	}
	return pb.MinerSignatureKind_MINER_SIGNATURE_KIND_UNSPECIFIED,
		fmt.Errorf("invalid kind %q: allowed values are name, argv, sha256", s)
}

func decodeMinerSignatureInput(args map[string]interface{}) (pb.MinerSignatureKind, minerSignatureInput, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return 0, minerSignatureInput{}, fmt.Errorf("invalid arguments: %w", err)
	}
	var in minerSignatureInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return 0, in, fmt.Errorf("invalid arguments: %w", err)
	}
	if in.Kind == "" {
		return 0, in, fmt.Errorf("kind is required (name, argv or sha256)")
	}
	k, err := parseMinerSignatureKind(in.Kind)
	if err != nil {
		return 0, in, err
	}
	// The pattern is not trimmed: an argv marker may carry significant
	// trailing whitespace ("--coin ").
	if in.Pattern == "" {
		return 0, in, fmt.Errorf("pattern is required")
	}
	return k, in, nil
}

func handleListMinerSignatures(client API, _ map[string]interface{}) (string, error) {
	resp, err := client.ListMinerSignatures()
	if err != nil {
		return "", fmt.Errorf("list miner signatures: %w", err)
	}
	return marshalProto(resp)
}

func handleAddMinerSignature(client API, args map[string]interface{}) (string, error) {
	k, in, err := decodeMinerSignatureInput(args)
	if err != nil {
		return "", err
	}
	resp, err := client.AddMinerSignature(&pb.AddMinerSignatureRequest{
		Signature: &pb.MinerSignature{Kind: k, Pattern: in.Pattern, Label: in.Label},
	})
	if err != nil {
		return "", fmt.Errorf("add miner signature: %w", err)
	}
	return marshalProto(resp)
}

func handleRemoveMinerSignature(client API, args map[string]interface{}) (string, error) {
	k, in, err := decodeMinerSignatureInput(args)
	if err != nil {
		return "", err
	}
	resp, err := client.RemoveMinerSignature(k, in.Pattern)
	if err != nil {
		return "", fmt.Errorf("remove miner signature: %w", err)
	}
	return marshalProto(resp)
}

// ListMinerSignatures reads GET /v1/security/miner-signatures.
func (c *Client) ListMinerSignatures() (*pb.ListMinerSignaturesResponse, error) {
	out := &pb.ListMinerSignaturesResponse{}
	if err := c.processPolicyRoundTrip("GET", minerSignaturesPath, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddMinerSignature posts POST /v1/security/miner-signatures.
func (c *Client) AddMinerSignature(req *pb.AddMinerSignatureRequest) (*pb.AddMinerSignatureResponse, error) {
	out := &pb.AddMinerSignatureResponse{}
	if err := c.processPolicyRoundTrip("POST", minerSignaturesPath, req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveMinerSignature calls DELETE /v1/security/miner-signatures?kind=&pattern=.
// kind and pattern travel as query parameters (an argv marker can hold
// slashes and spaces), matching the CLI.
func (c *Client) RemoveMinerSignature(kind pb.MinerSignatureKind, pattern string) (*pb.RemoveMinerSignatureResponse, error) {
	q := url.Values{"kind": {kind.String()}, "pattern": {pattern}}
	out := &pb.RemoveMinerSignatureResponse{}
	if err := c.processPolicyRoundTrip("DELETE", minerSignaturesPath+"?"+q.Encode(), nil, out); err != nil {
		return nil, err
	}
	return out, nil
}
