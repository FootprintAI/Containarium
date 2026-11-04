package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
)

// `containarium code skill-sets` (#3374) re-applies a box's SDLC skill sets
// through the daemon's ApplyBoxSkillSets: the thin CLI over the same call a
// control plane makes when a tenant's skill sets change. `code install
// --skill-sets` sets them when the agent is first installed, over SSH; this
// changes them afterwards, with no SSH client, on a box that already exists.

var (
	codeSkillSetsValue   string
	codeSkillSetsRelease string
)

var codeSkillSetsCmd = &cobra.Command{
	Use:   "skill-sets <box>",
	Short: "Re-apply a box's SDLC skill sets without re-creating it",
	Long: `Make a running box's installed SDLC skill sets exactly --skill-sets, through
the daemon (#3374). Newly listed sets are installed; sets the box's manifest
records and the list omits are removed, deleting only the skill directories
that set installed; the files of sets kept are refreshed to the release's pin.
Skills you installed by hand under ~/.claude/skills are never touched.

This is the "later" half of ` + "`containarium code install --skill-sets`" + `: install
sets the selection when the agent first lands on the box (over SSH, as part of
installing the engine); this command changes it afterwards, with no SSH client,
through the same installer and the same lock (pkg/core/sdlcskills/sdlc-skills.lock).
A set installed by ` + "`code install`" + ` or the recipe before the daemon kept its
per-box manifest can be adopted by keeping it in the list; omitting it is refused
(SET_PREDATES_MANIFEST) until it has been adopted once.

--skill-sets is the complete target list: a comma-separated list of set ids
(for example sdlc,qa), "all" (every set this CLI's lock defines), or "none"
(remove every set the manifest records). An unknown id is refused by the daemon,
naming the known ones. The call is idempotent: repeating it reports "unchanged".
A box with a run in progress (a running code run, or a skill run in it) is
refused (RUN_IN_PROGRESS); retry once it has ended, or stop it first.

--release picks the Containarium release whose installer, lock and skills bundle
the box fetches (default: the daemon's own). The box needs to reach GitHub, as
for ` + "`code install`" + `.

Examples:
  containarium code skill-sets alice --skill-sets sdlc,qa --server <host>
  containarium code skill-sets alice --skill-sets none --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeSkillSets,
}

func init() {
	codeCmd.AddCommand(codeSkillSetsCmd)
	codeSkillSetsCmd.Flags().StringVar(&codeSkillSetsValue, "skill-sets", "",
		"the complete target list: comma-separated set ids (for example sdlc,qa), \"all\", or \"none\"")
	_ = codeSkillSetsCmd.MarkFlagRequired("skill-sets")
	codeSkillSetsCmd.Flags().StringVar(&codeSkillSetsRelease, "release", "",
		"Containarium release tag whose installer, lock and skills bundle to use (default: the daemon's own)")
}

// boxSkillSetApplier is what the command needs from a daemon client.
type boxSkillSetApplier interface {
	ApplyBoxSkillSets(req *pb.ApplyBoxSkillSetsRequest) (*pb.ApplyBoxSkillSetsResponse, error)
}

func runCodeSkillSets(cmd *cobra.Command, args []string) error {
	if err := validateBoxName(args[0]); err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	var c interface {
		boxSkillSetApplier
		Close() error
	}
	var err error
	if httpMode {
		c, err = client.NewHTTPClient(serverAddr, authToken)
	} else {
		c, err = client.NewGRPCClient(serverAddr, certsDir, insecure)
	}
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return codeApplySkillSets(c, args[0], codeSkillSetsValue, codeSkillSetsRelease, os.Stdout)
}

// resolveSkillSetTarget turns the --skill-sets value into the RPC's explicit
// target list: ids as given, "none" as the empty list, and "all" as every set
// this CLI's embedded lock defines (the daemon still validates each id against
// its own lock). An empty value is an error: the list is the whole request.
func resolveSkillSetTarget(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("--skill-sets is required: the complete target list (set ids, \"all\" or \"none\")")
	}
	sets, err := sdlcskills.ParseSkillSets(value)
	if err != nil {
		return nil, fmt.Errorf("--skill-sets: %w", err)
	}
	switch {
	case sets.None():
		return []string{}, nil
	case sets.All():
		lock, err := sdlcskills.Embedded()
		if err != nil {
			return nil, fmt.Errorf("--skill-sets all: read this CLI's skill-set lock: %w", err)
		}
		ids := make([]string, 0, len(lock.Sets))
		for id := range lock.Sets {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return ids, nil
	}
	return sets.IDs(), nil
}

func codeApplySkillSets(c boxSkillSetApplier, box, value, release string, w io.Writer) error {
	target, err := resolveSkillSetTarget(value)
	if err != nil {
		return err
	}
	if release = strings.TrimSpace(release); release != "" && !sdlcskills.ValidReleaseTag(release) {
		return fmt.Errorf("--release %q is not a release tag (expected something like v0.89.0)", release)
	}
	resp, err := c.ApplyBoxSkillSets(&pb.ApplyBoxSkillSetsRequest{Username: box, SkillSets: target, Release: release})
	if isUnimplemented(err) {
		return fmt.Errorf("this daemon does not support re-applying skill sets (ApplyBoxSkillSets); upgrade it, or re-run `containarium code install %s --skill-sets %s`", box, value)
	}
	if err != nil {
		if reason := skillSetsRefusalOf(err); reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED {
			return fmt.Errorf("apply skill sets on %s: refused (%s): %s", box, strings.TrimPrefix(reason.String(), "BOX_SKILL_SETS_REFUSAL_"), status.Convert(err).Message())
		}
		return fmt.Errorf("apply skill sets on %s: %w", box, err)
	}
	_, err = io.WriteString(w, renderSkillSetsApply(box, resp))
	return err
}

// skillSetsRefusalOf returns the typed reason a refusal carries in its status
// details (a PreconditionFailure violation type or a BadRequest field
// violation reason spelled as a BoxSkillSetsRefusal name), or UNSPECIFIED.
// Details travel on the gRPC transport; the HTTP client surfaces the message
// only, which already says why.
func skillSetsRefusalOf(err error) pb.BoxSkillSetsRefusal {
	st, ok := status.FromError(err)
	if !ok {
		return pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED
	}
	for _, d := range st.Details() {
		switch p := d.(type) {
		case *errdetails.PreconditionFailure:
			for _, v := range p.GetViolations() {
				if r, ok := pb.BoxSkillSetsRefusal_value[v.GetType()]; ok {
					return pb.BoxSkillSetsRefusal(r)
				}
			}
		case *errdetails.BadRequest:
			for _, v := range p.GetFieldViolations() {
				if r, ok := pb.BoxSkillSetsRefusal_value[v.GetReason()]; ok {
					return pb.BoxSkillSetsRefusal(r)
				}
			}
		}
	}
	return pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNSPECIFIED
}

// renderSkillSetsApply prints the sets the box now has and what this call
// installed and removed, or that nothing changed.
func renderSkillSetsApply(box string, resp *pb.ApplyBoxSkillSetsResponse) string {
	sets := "none"
	if len(resp.GetSkillSets()) > 0 {
		sets = strings.Join(resp.GetSkillSets(), ", ")
	}
	var b strings.Builder
	if resp.GetUnchanged() {
		fmt.Fprintf(&b, "%s: skill sets unchanged (%s); nothing installed or removed, files refreshed from %s\n", box, sets, resp.GetRelease())
		return b.String()
	}
	fmt.Fprintf(&b, "%s: skill sets now %s (from %s)\n", box, sets, resp.GetRelease())
	for _, c := range resp.GetInstalled() {
		fmt.Fprintf(&b, "  installed %s: %s\n", c.GetSkillSet(), strings.Join(c.GetSkills(), ", "))
	}
	for _, c := range resp.GetRemoved() {
		set := c.GetSkillSet()
		if set == "" {
			set = "(no set in this release's lock)"
		}
		fmt.Fprintf(&b, "  removed %s: %s\n", set, strings.Join(c.GetSkills(), ", "))
	}
	return b.String()
}
