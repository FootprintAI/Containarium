package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	"github.com/spf13/cobra"
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
refused (RUN_IN_PROGRESS); retry once it has ended, or stop it first. An apply
that waited 30s for the box and found it still held is refused too: APPLY_IN_PROGRESS
when another apply on the box was still installing, RUN_IN_PROGRESS when run starts
held it (the message names those still in flight); retry shortly.

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
type boxSkillSetApplier = client.BoxSkillSetApplier

func runCodeSkillSets(cmd *cobra.Command, args []string) error {
	if err := client.ValidateBoxName(args[0]); err != nil {
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
	resp, err := client.ApplySkillSets(c, box, target, release)
	if isUnimplemented(err) {
		return fmt.Errorf("this daemon does not support re-applying skill sets (ApplyBoxSkillSets); upgrade it, or re-run `containarium code install %s --skill-sets %s`", box, value)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, client.RenderSkillSetsApply(box, resp))
	return err
}
