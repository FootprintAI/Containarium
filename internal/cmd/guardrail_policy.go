package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium guardrail policy get|set` — the server-side guardrail policy
// (#2368; docs/architecture/guardrail-inbound-and-server-policy.md). Unlike
// the other guardrail verbs, these talk to the daemon: the policy lives on
// the platform. They carry no dataset content.

var (
	guardrailPolicyJSON    bool
	guardrailPolicySetFile string
)

// guardrailPolicyAPI is the slice of the typed clients these verbs use; both
// client.GRPCClient and client.HTTPClient satisfy it.
type guardrailPolicyAPI interface {
	GetGuardrailPolicy() (*pb.GetGuardrailPolicyResponse, error)
	SetGuardrailPolicy(req *pb.SetGuardrailPolicyRequest) (*pb.SetGuardrailPolicyResponse, error)
}

// errNoGuardrailServer is newGuardrailPolicyAPI's answer when no --server is
// configured. `policy get|set` report it; `apply` and `verify` read it as "no
// daemon", their local mode (guardrail_server.go).
var errNoGuardrailServer = errors.New("--server is required for guardrail policy commands")

// newGuardrailPolicyAPI builds the client from the global --server/--http
// flags. A variable so tests can substitute a fake.
var newGuardrailPolicyAPI = func() (guardrailPolicyAPI, func(), error) {
	if serverAddr == "" {
		return nil, nil, errNoGuardrailServer
	}
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, nil, err
		}
		return h, func() { _ = h.Close() }, nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, nil, err
	}
	return g, func() { _ = g.Close() }, nil
}

var guardrailPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Read or replace the server-side guardrail policy (talks to the daemon)",
}

var guardrailPolicyGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the server's guardrail policy, trusted signers, revision and hash",
	Long: `Print the cluster-wide guardrail policy. Any authenticated caller may
read it. "not configured" means no policy was ever set.

Examples:
  containarium guardrail policy get --server <host>:50051
  containarium guardrail policy get --json`,
	Args: cobra.NoArgs,
	RunE: runGuardrailPolicyGet,
}

var guardrailPolicySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Replace the server's guardrail policy (admin only)",
	Long: `Replace the cluster-wide guardrail policy and its trusted signers from
--file: the JSON form of SetGuardrailPolicyRequest, for example

  {"policy": {"rules": [
     {"kind": "GUARDRAIL_KIND_PII", "action": "GUARDRAIL_ACTION_REDACT", "maxResidual": 0},
     {"kind": "GUARDRAIL_KIND_SECRET", "action": "GUARDRAIL_ACTION_BLOCK"}]},
   "trustedSigners": [{"keyId": "<sha256 of the key, hex>", "publicKey": "<base64 ed25519 key>", "label": "release key"}]}

The file is validated locally, then by the daemon. Admin role required;
every change increments the revision and is audited.`,
	Args: cobra.NoArgs,
	RunE: runGuardrailPolicySet,
}

func init() {
	guardrailPolicyCmd.AddCommand(guardrailPolicyGetCmd, guardrailPolicySetCmd)
	guardrailCmd.AddCommand(guardrailPolicyCmd)
	guardrailPolicyGetCmd.Flags().BoolVar(&guardrailPolicyJSON, "json", false, "Print the response as JSON")
	guardrailPolicySetCmd.Flags().StringVar(&guardrailPolicySetFile, "file", "", "SetGuardrailPolicyRequest as JSON (required)")
	_ = guardrailPolicySetCmd.MarkFlagRequired("file")
}

func runGuardrailPolicyGet(cmd *cobra.Command, _ []string) error {
	api, done, err := newGuardrailPolicyAPI()
	if err != nil {
		return err
	}
	defer done()
	resp, err := api.GetGuardrailPolicy()
	if err != nil {
		return err
	}
	if guardrailPolicyJSON {
		b, err := protojson.MarshalOptions{Multiline: true}.Marshal(resp)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	_, err = fmt.Fprint(cmd.OutOrStdout(), guardrailpolicy.Describe(resp))
	return err
}

func runGuardrailPolicySet(cmd *cobra.Command, _ []string) error {
	data, err := os.ReadFile(guardrailPolicySetFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}
	req, err := guardrailpolicy.ParseSetRequest(data)
	if err != nil {
		return err
	}
	if err := guardrailpolicy.Validate(req.GetPolicy(), req.GetTrustedSigners()); err != nil {
		return fmt.Errorf("invalid guardrail policy: %w", err)
	}
	api, done, err := newGuardrailPolicyAPI()
	if err != nil {
		return err
	}
	defer done()
	resp, err := api.SetGuardrailPolicy(req)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Guardrail policy stored: revision %d, policy hash %s\n",
		resp.GetPolicy().GetRevision(), resp.GetPolicyHash())
	return err
}
