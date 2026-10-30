//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/proofpack"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium proof-pack verify` (#2798). Like `audit verify`, it reads the
// audit chain straight from Postgres, so it is a server-side command.

// proofPackVerifyChain opens the audit chain verify checks against; tests
// replace it.
var proofPackVerifyChain = func(ctx context.Context) (proofpack.SealChain, func(), error) {
	store, cleanup, err := openAuditStore(ctx)
	if err != nil {
		return nil, nil, err
	}
	return store, cleanup, nil
}

// proofPackVerifyAPI is the one call --server makes; both client.GRPCClient
// and client.HTTPClient satisfy it (#3064).
type proofPackVerifyAPI interface {
	VerifyProofPack(ctx context.Context, sealed *pb.SealedProofPack) (*pb.VerifyProofPackResponse, error)
}

// newProofPackVerifyAPI dials the daemon named by the global --server/--http
// flags; tests replace it.
var newProofPackVerifyAPI = func() (proofPackVerifyAPI, func(), error) {
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

var proofPackVerifyCmd = &cobra.Command{
	Use:   "verify <pack.json>",
	Short: "Verify a sealed Proof Pack against its audit chain entry",
	Long: `Verify a sealed Proof Pack, the file attached to an agent-opened PR.

It recomputes every step's log digest and the digest of every step and of
the pack header, and compares them with the seal row in the audit hash
chain that the pack's seal points at. It then walks the chain from that row
to the tip. The first part that does not match is named:

  proofpack: step 1 ("lint"): digest ... does not match sealed ...

The seal row stays verifiable after retention purges older rows of the
chain. Once retention purges the seal row itself, verify says so and exits
non-zero. The chain walk proves internal consistency only; run
'audit verify-anchor' to rule out a rewrite-and-recompute of the chain.

Direct Postgres access, configured as for 'audit verify'.

With --server on the command line, the pack is sent to that daemon's
VerifyProofPack API instead (needs the audit:read scope), so it works from
any machine; no Postgres is read. A daemon's "ok" is only as trustworthy as
the daemon: for stronger assurance compare the chain tip hash it prints with
the external anchor, or verify on the daemon host. A server address from the
environment or config does not switch modes; only --server does.`,
	Example: `  containarium proof-pack verify proof-pack.json
  containarium proof-pack verify proof-pack.json --server https://daemon.example.com --http`,
	Args: cobra.ExactArgs(1),
	RunE: runProofPackVerify,
}

func init() {
	proofPackCmd.AddCommand(proofPackVerifyCmd)
}

func runProofPackVerify(cmd *cobra.Command, args []string) error {
	b, err := os.ReadFile(args[0]) // #nosec G304 -- operator-chosen pack file
	if err != nil {
		return err
	}
	var sealed pb.SealedProofPack
	if err := protojson.Unmarshal(b, &sealed); err != nil {
		return fmt.Errorf("%s is not a sealed proof pack: %w", args[0], err)
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	// InheritedFlags merges the root's persistent flags into cmd.Flags().
	cmd.InheritedFlags()
	if cmd.Flags().Changed("server") {
		return verifyProofPackViaServer(ctx, cmd, &sealed)
	}
	chain, cleanup, err := proofPackVerifyChain(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	res, err := proofpack.Verify(ctx, chain, &sealed)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "proof pack %s: %d step(s) match the seal at audit row %d; audit chain intact through id %d\n",
		res.PackSHA256, res.Steps, res.AuditRowID, res.ChainCheckedThrough)
	return nil
}

// verifyProofPackViaServer sends the pack to the daemon and reports its
// verdict; anything but OK is an error, so the exit status is non-zero.
func verifyProofPackViaServer(ctx context.Context, cmd *cobra.Command, sealed *pb.SealedProofPack) error {
	api, cleanup, err := newProofPackVerifyAPI()
	if err != nil {
		return err
	}
	defer cleanup()
	resp, err := api.VerifyProofPack(ctx, sealed)
	if err != nil {
		return err
	}
	switch resp.GetVerdict() {
	case pb.ProofPackVerdict_PROOF_PACK_VERDICT_OK:
		fmt.Fprintf(cmd.OutOrStdout(), "proof pack %s: %d step(s) match the seal at audit row %d, according to the daemon; audit chain intact through id %d (tip hash %s)\n"+
			"compare the tip hash with the external anchor: a daemon's ok is weaker than verifying offline\n",
			resp.GetPackSha256(), resp.GetStepsChecked(), resp.GetAuditRowId(), resp.GetChainTipId(), resp.GetChainTipHash())
		return nil
	case pb.ProofPackVerdict_PROOF_PACK_VERDICT_MISMATCH:
		m := resp.GetFirstMismatch()
		if m.GetHeader() {
			return fmt.Errorf("pack header does not match the seal: %s", m.GetReason())
		}
		return fmt.Errorf("step %d (%q) does not match the seal: %s", m.GetStepIndex(), m.GetName(), m.GetReason())
	case pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_PURGED:
		return fmt.Errorf("the seal's audit row was purged by retention (or never issued: the daemon cannot tell the two apart); the pack can no longer be checked against the chain")
	default:
		return fmt.Errorf("daemon verdict %s: %s", resp.GetVerdict(), resp.GetMessage())
	}
}
