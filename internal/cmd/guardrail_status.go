package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium guardrail status` — what scans model responses on the daemon
// (#2737): none, baseline or admin. Talks to the daemon, like `policy get`.

var guardrailStatusJSON bool

// guardrailStatusAPI is the slice of the typed clients `status` uses.
type guardrailStatusAPI interface {
	GetGuardrailStatus() (*pb.GetGuardrailStatusResponse, error)
}

// newGuardrailStatusAPI builds the client from the global flags. A variable
// so tests can substitute a fake.
var newGuardrailStatusAPI = func() (guardrailStatusAPI, func(), error) {
	return dialGuardrailPolicyService()
}

var guardrailStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which guardrail policy scans model responses: none, baseline or admin",
	Long: `Print the effective response guardrail policy on the daemon. Any
authenticated caller may read it.

  baseline  no admin policy was ever set: responses are scanned with the
            built-in rules (private keys, cloud keys), log-only
  admin     the admin policy has an inbound BLOCK rule: it decides what is
            scanned and blocked, and the baseline is off
  none      an admin policy is set but has no inbound BLOCK rule: responses
            are not scanned

Examples:
  containarium guardrail status --server <host>:50051
  containarium guardrail status --json`,
	Args: cobra.NoArgs,
	RunE: runGuardrailStatus,
}

func init() {
	guardrailCmd.AddCommand(guardrailStatusCmd)
	guardrailStatusCmd.Flags().BoolVar(&guardrailStatusJSON, "json", false, "Print the response as JSON")
}

func runGuardrailStatus(cmd *cobra.Command, _ []string) error {
	api, done, err := newGuardrailStatusAPI()
	if err != nil {
		return err
	}
	defer done()
	resp, err := api.GetGuardrailStatus()
	if err != nil {
		return err
	}
	if guardrailStatusJSON {
		b, err := protojson.MarshalOptions{Multiline: true}.Marshal(resp)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	_, err = fmt.Fprint(cmd.OutOrStdout(), guardrailpolicy.DescribeStatus(resp))
	return err
}
