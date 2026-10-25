//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

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

Direct Postgres access, configured as for 'audit verify'.`,
	Example: `  containarium proof-pack verify proof-pack.json`,
	Args:    cobra.ExactArgs(1),
	RunE:    runProofPackVerify,
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
