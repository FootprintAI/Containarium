package mcp

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// apply_box_skill_sets (#3511) is the MCP twin of `containarium code
// skill-sets`: a thin wrapper over client.ApplySkillSets, the function the CLI
// calls, over the same REST path. CLI-first (CLAUDE.md): no endpoint of its own.

// applySkillSetsFn is that shared function. A variable only so a test can
// check it is the CLI's.
var applySkillSetsFn = client.ApplySkillSets

// newSkillSetsAPI builds the CLI's typed HTTP client from this MCP client's
// transport, base URL and current token. A variable so a test can fake it.
var newSkillSetsAPI = func(c *Client) (*client.HTTPClient, error) {
	if c.tlsConfigErr != nil {
		return nil, fmt.Errorf("MCP client refuses to send request: %w", c.tlsConfigErr)
	}
	token, err := c.readToken()
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	return client.NewHTTPClient(c.baseURL, token, client.WithHTTPClient(c.httpClient))
}

// ApplyBoxSkillSets runs the shared apply over this client.
func (c *Client) ApplyBoxSkillSets(box string, skillSets []string, release string) (*pb.ApplyBoxSkillSetsResponse, error) {
	hc, err := newSkillSetsAPI(c)
	if err != nil {
		return nil, err
	}
	defer func() { _ = hc.Close() }()
	return applySkillSetsFn(hc, box, skillSets, release)
}

func applyBoxSkillSetsTool() Tool {
	return Tool{
		Name: "apply_box_skill_sets",
		Description: "Make a running box's installed SDLC skill sets exactly 'skill_sets'. Newly listed " +
			"sets are installed; sets the box's manifest records and the list omits are removed " +
			"(only the skill directories that set installed; skills installed by hand are never " +
			"touched); the files of sets kept are refreshed to the release's pin. Idempotent: " +
			"repeating it reports 'unchanged'. An empty array removes every set. Refused with a " +
			"typed reason, shown as 'refused (REASON)': RUN_IN_PROGRESS (a run is active in the " +
			"box, or run starts held the box for 30s; retry once it ends), APPLY_IN_PROGRESS " +
			"(another apply on the box was still installing after 30s; retry once it returns), SET_PREDATES_MANIFEST (a set installed before the per-box " +
			"manifest existed would be removed; keep it in the list once to adopt it), " +
			"UNKNOWN_SKILL_SET (an id the release's lock does not define). " +
			"Same function as `containarium code skill-sets`.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"box": map[string]interface{}{
					"type":        "string",
					"description": "The box (owner username) to change. Mirrors the <box> argument.",
				},
				"skill_sets": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "The complete target list of set ids (for example [\"sdlc\", \"qa\"]). An empty array removes every set; there is no \"all\" literal. Mirrors --skill-sets.",
				},
				"release": map[string]interface{}{
					"type":        "string",
					"description": "Containarium release tag whose installer, lock and skills bundle to use (for example v0.89.0). Default: the daemon's own. Mirrors --release.",
				},
			},
			"required": []string{"box", "skill_sets"},
		},
		Handler: handleApplyBoxSkillSets,
	}
}

// applySkillSetsArgs is the tool's decoded, validated arguments.
type applySkillSetsArgs struct {
	Box       string
	SkillSets []string
	Release   string
}

// parseApplySkillSetsArgs validates the arguments before any request is made.
// The release tag is checked again by client.ApplySkillSets; checking it here
// keeps every refusal ahead of the transport.
func parseApplySkillSetsArgs(args map[string]interface{}) (applySkillSetsArgs, error) {
	out := applySkillSetsArgs{
		Box:     getStringArg(args, "box", ""),
		Release: getStringArg(args, "release", ""),
	}
	if err := client.ValidateBoxName(out.Box); err != nil {
		return out, err
	}
	if out.Release != "" && !sdlcskills.ValidReleaseTag(out.Release) {
		return out, fmt.Errorf("release %q is not a release tag (expected something like v0.89.0)", out.Release)
	}
	raw, ok := args["skill_sets"].([]interface{})
	if !ok {
		return out, fmt.Errorf("skill_sets is required: an array of set ids (an empty array removes every set)")
	}
	out.SkillSets = make([]string, 0, len(raw))
	for _, v := range raw {
		id, ok := v.(string)
		if !ok {
			return out, fmt.Errorf("skill_sets: every entry must be a string set id, got %v", v)
		}
		// One id per entry: ParseSkillSets yields exactly that id and nothing
		// for the "all"/"none" literals or a comma list.
		parsed, err := sdlcskills.ParseSkillSets(id)
		if err != nil || len(parsed.IDs()) != 1 || parsed.IDs()[0] != id {
			return out, fmt.Errorf("skill_sets: %q is not a set id (want [a-z0-9-]+; \"all\" and \"none\" are not accepted, use an explicit list or an empty array)", id)
		}
		out.SkillSets = append(out.SkillSets, id)
	}
	return out, nil
}

func handleApplyBoxSkillSets(api API, args map[string]interface{}) (string, error) {
	p, err := parseApplySkillSetsArgs(args)
	if err != nil {
		return "", err
	}
	resp, err := api.ApplyBoxSkillSets(p.Box, p.SkillSets, p.Release)
	if status.Code(err) == codes.Unimplemented {
		return "", fmt.Errorf("this daemon does not support re-applying skill sets (ApplyBoxSkillSets); upgrade it")
	}
	if err != nil {
		return "", err
	}
	return client.RenderSkillSetsApply(p.Box, resp), nil
}
