//go:build !containarium_client

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/proofpack"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium proof-pack` — evidence that a repository's tests ran,
// recorded by the platform rather than claimed by the coding agent
// (docs/PROOF-PACK.md, #2366). generate runs on the host that owns the box
// and execs into it through the local Incus backend, the same
// proofpack.Generate the daemon calls; it is a server-side command, so the
// client binary does not carry it.
var proofPackCmd = &cobra.Command{
	Use:   "proof-pack",
	Short: "Generate a Proof Pack: the repo's tests run in a box, with outcomes and logs",
}

var (
	proofPackDir         string
	proofPackOut         string
	proofPackStepTimeout time.Duration
)

// proofPackExecer is the backend generate execs through; tests replace it.
var proofPackExecer = func() (proofpack.Execer, error) { return incus.New() }

var proofPackGenerateCmd = &cobra.Command{
	Use:   "generate <container>",
	Short: "Run the repo's declared test commands in a box and write the Proof Pack",
	Long: `Run the repository's test command set inside <container>, from --dir,
and write the resulting Proof Pack as JSON to --out (stdout by default).

The commands are the "test:" key of the repository's
.github/containarium.yml, either one command or a list of steps:

  test: make check

  test:
    - name: unit
      kind: unit            # unit | integration | e2e | static_analysis | security_scan | test
      run: go test ./...
    - name: lint
      kind: static_analysis
      run: golangci-lint run

With no "test:" key the fallback is "make test" when the repository has a
Makefile; otherwise nothing runs and the pack's status is NO_COMMANDS.

Each step runs as root in the box, under --step-timeout, with its combined
stdout and stderr kept up to the last 256 KiB. The pack records each
step's declared name, kind, exit status, duration, log and the log's
SHA-256. It never records the command lines or the environment.

Exit status: 0 when the pack's status is PASSED; 1 when it is FAILED or
NO_COMMANDS (the pack is written either way); non-zero without a pack
when the commands could not be run at all.

Example:
  containariumd proof-pack generate <tenant>-container --dir /workspace --out pack.json`,
	Args: cobra.ExactArgs(1),
	RunE: runProofPackGenerate,
}

func init() {
	proofPackCmd.AddCommand(proofPackGenerateCmd)
	rootCmd.AddCommand(proofPackCmd)

	proofPackGenerateCmd.Flags().StringVar(&proofPackDir, "dir", proofpack.DefaultRepoDir, "Repository directory inside the box")
	proofPackGenerateCmd.Flags().StringVarP(&proofPackOut, "out", "o", "", "File to write the pack JSON to (default stdout)")
	proofPackGenerateCmd.Flags().DurationVar(&proofPackStepTimeout, "step-timeout", proofpack.DefaultStepTimeout, "Time limit for each step")
}

func runProofPackGenerate(cmd *cobra.Command, args []string) error {
	ex, err := proofPackExecer()
	if err != nil {
		return fmt.Errorf("connect to incus: %w", err)
	}
	pack, err := proofpack.Generate(cmd.Context(), ex, args[0], proofpack.Options{
		RepoDir:     proofPackDir,
		StepTimeout: proofPackStepTimeout,
	})
	if err != nil {
		return err
	}
	out, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(pack)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if proofPackOut == "" {
		if _, err := cmd.OutOrStdout().Write(out); err != nil {
			return err
		}
	} else if err := os.WriteFile(proofPackOut, out, 0o600); err != nil {
		return err
	}

	digest, err := proofpack.PackDigest(pack)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "proof pack: %s, %d step(s), sha256 %s\n",
		pack.GetStatus(), len(pack.GetSteps()), digest)
	if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED {
		return fmt.Errorf("proof pack status is %s", pack.GetStatus())
	}
	return nil
}
