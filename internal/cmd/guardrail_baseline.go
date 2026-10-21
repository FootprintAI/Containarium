package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium guardrail baseline set --mode block|log` — the admin-only,
// audited switch for the baseline response scan (#2738, slice C of #2575).
// A thin client over GuardrailPolicyService.SetGuardrailBaselineMode
// (PUT /v1/guardrail/baseline).

var guardrailBaselineMode string

// guardrailBaselineAPI is the slice of the typed clients `baseline set` uses.
type guardrailBaselineAPI interface {
	SetGuardrailBaselineMode(mode pb.GuardrailBaselineMode) (*pb.SetGuardrailBaselineModeResponse, error)
}

// newGuardrailBaselineAPI builds the client from the global flags. A
// variable so tests can substitute a fake.
var newGuardrailBaselineAPI = func() (guardrailBaselineAPI, func(), error) {
	return dialGuardrailPolicyService()
}

// guardrailBaselineModes maps the --mode words onto the proto enum.
var guardrailBaselineModes = map[string]pb.GuardrailBaselineMode{
	"log":   pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_LOG,
	"block": pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_BLOCK,
}

var guardrailBaselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Configure the baseline response scan (talks to the daemon)",
}

var guardrailBaselineSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Switch the baseline response scan between log and block (admin only)",
	Long: `Switch what the baseline does with a match. The baseline scans model
responses only while no admin guardrail policy has been set.

  log    default: the response streams to the client unchanged and is
         scanned at its end; a match is audited and logged
  block  the response is held to its end, scanned, and blocked on a match
         (HTTP 502, audited); a 2xx response over the hold limit, with a
         content encoding, or neither JSON nor an event stream is blocked
         too, for every tenant, as under an admin BLOCK rule

The mode is stored apart from the policy, so setting it never turns the
baseline off. Admin role required; every change increments the setting's
revision. On a daemon with an audit store the change writes an audit entry,
and it is refused if that entry cannot be written. A daemon with no audit
store (no Postgres, REST disabled, or an audit store that failed to start)
keeps no audit entry. Check it with 'containarium guardrail status'.

Examples:
  containarium guardrail baseline set --mode block --server <host>:50051
  containarium guardrail baseline set --mode log --server <host>:50051`,
	Args: cobra.NoArgs,
	RunE: runGuardrailBaselineSet,
}

func init() {
	guardrailBaselineCmd.AddCommand(guardrailBaselineSetCmd)
	guardrailCmd.AddCommand(guardrailBaselineCmd)
	guardrailBaselineSetCmd.Flags().StringVar(&guardrailBaselineMode, "mode", "", "log or block (required)")
	_ = guardrailBaselineSetCmd.MarkFlagRequired("mode")
}

func runGuardrailBaselineSet(cmd *cobra.Command, _ []string) error {
	mode, ok := guardrailBaselineModes[strings.ToLower(guardrailBaselineMode)]
	if !ok {
		return fmt.Errorf("--mode must be log or block, got %q", guardrailBaselineMode)
	}
	api, done, err := newGuardrailBaselineAPI()
	if err != nil {
		return err
	}
	defer done()
	resp, err := api.SetGuardrailBaselineMode(mode)
	if err != nil {
		return err
	}
	b := resp.GetBaseline()
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Baseline mode set to %s: revision %d, by %s\n",
		strings.ToLower(strings.TrimPrefix(b.GetMode().String(), "GUARDRAIL_BASELINE_MODE_")), b.GetRevision(), b.GetUpdatedBy())
	return err
}
