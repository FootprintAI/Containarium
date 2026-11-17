package cmd

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium guardrail dropin` — switch the daemon-installed guardrail
// hook drop-in per box and show coverage (#3762). The hook handler the
// drop-in runs is `containarium guardrail hook <event>`, a separate command.

var guardrailDropInJSON bool

// guardrailDropInAPI is the slice of the typed clients `dropin` uses.
type guardrailDropInAPI interface {
	SetGuardrailHook(username string, enabled bool) (*pb.GuardrailHookBoxCoverage, error)
	GetGuardrailHookCoverage(username string) (*pb.GuardrailHookBoxCoverage, error)
	ListGuardrailHookCoverage() ([]*pb.GuardrailHookBoxCoverage, error)
}

// newGuardrailDropInAPI builds the client from the global flags. A variable
// so tests can substitute a fake.
var newGuardrailDropInAPI = func() (guardrailDropInAPI, func(), error) {
	return dialGuardrailPolicyService()
}

var guardrailDropInCmd = &cobra.Command{
	Use:   "dropin",
	Short: "Install the guardrail hook into a box as a managed drop-in, and show coverage",
	Long: `The daemon can install the guardrail hook into a box as a root-owned
Claude Code managed-settings drop-in, which the box user's own settings
cannot switch off, together with a pinned copy of the hook binary. It then
checks every few minutes that both are still in place and that hooks fire.

Coverage is tamper-evident, not tamper-proof: a box user with sudo can
change things between two checks.`,
}

var guardrailDropInEnableCmd = &cobra.Command{
	Use:   "enable <box>",
	Short: "Switch the guardrail hook on for a box (admin)",
	Long: `Install the hook binary and the drop-in into the box, now if it is
running and at every later start. Running sessions pick the hooks up at
their next tool call.

Every hook blocks on failure. If the hook or its engine is broken, tools
in the box stop working until it is fixed or switched off with
'guardrail dropin disable'.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error { return runGuardrailDropInSet(cmd, args[0], true) },
}

var guardrailDropInDisableCmd = &cobra.Command{
	Use:   "disable <box>",
	Short: "Switch the guardrail hook off for a box and remove the drop-in (admin)",
	Long: `Remove the drop-in and the hook binary from the box. This is the
break-glass for a broken hook. On a stopped box the removal happens when
the box next starts.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error { return runGuardrailDropInSet(cmd, args[0], false) },
}

var guardrailDropInCoverageCmd = &cobra.Command{
	Use:   "coverage [box]",
	Short: "Show guardrail hook coverage per box",
	Long: `With a box name, show that box's switch and last coverage check (the
box's own tenant or an admin). With none, list every box that has the hook
switched on (admin).

  COVERED                          drop-in and binary in place, hooks firing
  NOT_COVERED_FEATURE_OFF          the hook is switched off for the box
  NOT_COVERED_NOT_INSTALLED        the drop-in or hook binary is missing
  NOT_COVERED_CLIENT_TOO_OLD       Claude Code is older than the daemon's minimum
  NOT_COVERED_ENGINE_NOT_RUNNING   the engine service is not active, or the
                                   box user cannot open its socket
  NOT_COVERED_HOOKS_NOT_FIRING     a long-running client has no hook stamp
  NOT_COVERED_TAMPERED             a file was changed, or another managed
                                   settings file sets disableAllHooks
  UNKNOWN                          not checked yet, box stopped, or check failed

Examples:
  containarium guardrail dropin coverage --server <host>:50051
  containarium guardrail dropin coverage alice --json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGuardrailDropInCoverage,
}

func init() {
	guardrailCmd.AddCommand(guardrailDropInCmd)
	guardrailDropInCmd.AddCommand(guardrailDropInEnableCmd, guardrailDropInDisableCmd, guardrailDropInCoverageCmd)
	guardrailDropInCmd.PersistentFlags().BoolVar(&guardrailDropInJSON, "json", false, "Print the response as JSON")
}

func runGuardrailDropInSet(cmd *cobra.Command, username string, enabled bool) error {
	api, done, err := newGuardrailDropInAPI()
	if err != nil {
		return err
	}
	defer done()
	box, err := api.SetGuardrailHook(username, enabled)
	if err != nil {
		return err
	}
	return printGuardrailHookBoxes(cmd.OutOrStdout(), []*pb.GuardrailHookBoxCoverage{box})
}

func runGuardrailDropInCoverage(cmd *cobra.Command, args []string) error {
	api, done, err := newGuardrailDropInAPI()
	if err != nil {
		return err
	}
	defer done()
	var boxes []*pb.GuardrailHookBoxCoverage
	if len(args) == 1 {
		box, err := api.GetGuardrailHookCoverage(args[0])
		if err != nil {
			return err
		}
		boxes = []*pb.GuardrailHookBoxCoverage{box}
	} else if boxes, err = api.ListGuardrailHookCoverage(); err != nil {
		return err
	}
	if len(boxes) == 0 && !guardrailDropInJSON {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "No box has the guardrail hook switched on.")
		return err
	}
	return printGuardrailHookBoxes(cmd.OutOrStdout(), boxes)
}

func printGuardrailHookBoxes(w io.Writer, boxes []*pb.GuardrailHookBoxCoverage) error {
	if guardrailDropInJSON {
		b, err := protojson.MarshalOptions{Multiline: true}.Marshal(&pb.ListGuardrailHookCoverageResponse{Boxes: boxes})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "BOX\tSWITCH\tCOVERAGE\tCLIENT\tCHECKED\tDETAIL")
	for _, b := range boxes {
		sw, checked, version := "off", "-", b.GetClientVersion()
		if b.GetEnabled() {
			sw = "on"
		}
		if ts := b.GetCheckedAt(); ts != nil {
			checked = ts.AsTime().UTC().Format(time.RFC3339)
		}
		switch {
		case version != "":
		case b.GetCheckedAt() != nil && !b.GetClientInstalled():
			version = "none"
		default:
			version = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", escapeControl(b.GetUsername()), sw,
			strings.TrimPrefix(b.GetCoverage().String(), "GUARDRAIL_HOOK_COVERAGE_"), escapeControl(version), checked, escapeControl(b.GetDetail()))
	}
	return tw.Flush()
}
