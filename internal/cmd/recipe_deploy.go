package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var (
	recipeDeployGPU       string
	recipeDeployBackendID string
	recipeDeployPool      string
	recipeDeployParams    []string

	recipeDeployGuardrailRef         string
	recipeDeployGuardrailAttestation string

	recipeDeploySSHKeys []string
)

// recipeSSHKeys reads each --ssh-key public-key file (a leading ~/ is the
// home directory) and returns the contents in flag order, the way
// `containarium create --ssh-key` reads its one key (#3514). No paths: nil.
func recipeSSHKeys(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(paths))
	for _, p := range paths {
		expanded := p
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("--ssh-key %s: failed to get home directory: %w", p, err)
			}
			expanded = filepath.Join(home, rest)
		}
		// #nosec G304 -- operator-supplied --ssh-key path; reading it is the
		// documented purpose of the flag (same as `create --ssh-key`).
		b, err := os.ReadFile(expanded)
		if err != nil {
			return nil, fmt.Errorf("--ssh-key %s: %w", expanded, err)
		}
		keys = append(keys, string(b))
	}
	return keys, nil
}

// recipeGuardrailInput builds guardrail_input for a guardrail-gated recipe
// (#2368) from --guardrail-staging-ref and --guardrail-attestation. Neither
// set: nil (an ungated deploy; a gated recipe then refuses on the daemon).
func recipeGuardrailInput(ref, attestationFile string) (*pb.GuardrailGateInput, error) {
	if ref == "" && attestationFile == "" {
		return nil, nil
	}
	if ref == "" || attestationFile == "" {
		return nil, fmt.Errorf("--guardrail-staging-ref and --guardrail-attestation go together")
	}
	b, err := os.ReadFile(attestationFile) // #nosec G304 -- operator-supplied --guardrail-attestation path
	if err != nil {
		return nil, err
	}
	att := &pb.GuardrailAttestation{}
	if err := protojson.Unmarshal(b, att); err != nil {
		return nil, fmt.Errorf("--guardrail-attestation %s: %w", attestationFile, err)
	}
	return &pb.GuardrailGateInput{StagingRef: ref, Attestation: att}, nil
}

var recipeDeployCmd = &cobra.Command{
	Use:   "deploy <recipe-id> <name>",
	Short: "Deploy a recipe as a new dedicated container",
	Long: `Provision a new dedicated container from a recipe, run the recipe's
image inside it, and expose its ports.

In v1 the recipe deploys on the backend that --server points at. To deploy on
a GPU node, point --server at that node's daemon and pass --gpu.

Examples:
  containarium recipe deploy ollama ol1 --gpu 0 --param model=llama3 --server <host>
  containarium recipe deploy ollama ol2 --gpu 0 --ssh-key ~/.ssh/id_ed25519.pub --server <host>
  containarium recipe deploy llamacpp lc1 --gpu 0 --param hf_repo=ggml-org/gemma-3-1b-it-GGUF --server <host>`,
	Args: cobra.ExactArgs(2),
	RunE: runRecipeDeploy,
}

func init() {
	recipeCmd.AddCommand(recipeDeployCmd)
	recipeDeployCmd.Flags().StringVar(&recipeDeployGPU, "gpu", "",
		"GPU device ID for passthrough (e.g. '0'); required for GPU recipes")
	recipeDeployCmd.Flags().StringVar(&recipeDeployBackendID, "backend-id", "",
		"Target backend ID (must be the local backend in v1)")
	recipeDeployCmd.Flags().StringVar(&recipeDeployPool, "pool", "",
		"Target pool (not supported in v1)")
	recipeDeployCmd.Flags().StringArrayVar(&recipeDeployParams, "param", nil,
		"Recipe parameter as key=value (repeatable)")
	recipeDeployCmd.Flags().StringVar(&recipeDeployGuardrailRef, "guardrail-staging-ref", "",
		"Guardrail-gated recipes: the staged dataset's directory under <staging root>/<your authenticated subject>/ on the daemon host (not <name>)")
	recipeDeployCmd.Flags().StringVar(&recipeDeployGuardrailAttestation, "guardrail-attestation", "",
		"Guardrail-gated recipes: the attestation 'guardrail apply' wrote for that dataset")
	recipeDeployCmd.Flags().StringArrayVar(&recipeDeploySSHKeys, "ssh-key", nil,
		"Path to an SSH public key file to authorize on the new box at create time (repeatable; optional)")
}

func runRecipeDeploy(cmd *cobra.Command, args []string) error {
	recipeID, name := args[0], args[1]

	params, err := parseKeyValues(recipeDeployParams)
	if err != nil {
		return err
	}
	guardrailInput, err := recipeGuardrailInput(recipeDeployGuardrailRef, recipeDeployGuardrailAttestation)
	if err != nil {
		return err
	}
	sshKeys, err := recipeSSHKeys(recipeDeploySSHKeys)
	if err != nil {
		return err
	}

	c, err := newRecipeClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Deploying recipe %q as %q...\n", recipeID, name)
	resp, err := c.DeployRecipe(recipeID, name, client.DeployRecipeOptions{
		GPU:            recipeDeployGPU,
		BackendID:      recipeDeployBackendID,
		Pool:           recipeDeployPool,
		Parameters:     params,
		GuardrailInput: guardrailInput,
		SSHKeys:        sshKeys,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ %s\n", resp.Message)
	if resp.Url != "" {
		fmt.Printf("  URL: %s\n", resp.Url)
	}
	if resp.Container != nil {
		fmt.Printf("  Container: %s (%s)\n", resp.Container.Name, resp.Container.State)
	}
	return nil
}

// parseKeyValues parses repeated "key=value" flags into a map.
func parseKeyValues(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid parameter %q (expected key=value)", p)
		}
		out[k] = v
	}
	return out, nil
}
