package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium guardrail signer rotate|revoke|bundle` (#2729; docs/architecture/
// guardrail-inbound-and-server-policy.md, "Signer rotation and revocation").
// Rotate and revoke are admin-only read-edit-writes over SetGuardrailPolicy
// that send expected_revision, so a concurrent Set is ABORTED, not overwritten.
// Key custody is out of scope: private keys stay with the data owner.

var (
	guardrailSignerAdd    string
	guardrailSignerLabel  string
	guardrailSignerReason string
	guardrailSignerOut    string
	guardrailTrustBundle  string
)

var guardrailSignerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Rotate or revoke trusted attestation signers (talks to the daemon)",
}

var guardrailSignerRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Trust a new signing key next to the existing ones (admin only)",
	Long: `Add the public key in --add to the server's trusted signers and keep the
old ones, so attestations they signed still verify. Retire the old key with
'guardrail signer revoke' once owners have re-attested.

Example:
  containarium guardrail signer rotate --add ./new.pub --label 2026-q4 --server <host>:50051`,
	Args: cobra.NoArgs,
	RunE: runGuardrailSignerRotate,
}

var guardrailSignerRevokeCmd = &cobra.Command{
	Use:   "revoke <key-id>",
	Short: "Permanently revoke a signing key (admin only)",
	Long: `Revoke the key with SHA-256 id <key-id>. Every attestation it signed then
fails verification, whatever its attested_at, and the key is dropped from the
trusted signers. Revocation cannot be undone. --reason is required and is
named by every refused verify.

Example:
  containarium guardrail signer revoke <key-id> --reason "laptop lost" --server <host>:50051`,
	Args: cobra.ExactArgs(1),
	RunE: runGuardrailSignerRevoke,
}

var guardrailSignerBundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Export the server's trusted signers and revoked keys as protojson",
	Long: `Write the GuardrailTrustBundle (trusted signers and revoked keys) to --out, or
stdout. Hand the file to 'guardrail verify --trust-bundle' on a machine with no
server access. Any authenticated caller may export it.`,
	Args: cobra.NoArgs,
	RunE: runGuardrailSignerBundle,
}

func init() {
	guardrailSignerCmd.AddCommand(guardrailSignerRotateCmd, guardrailSignerRevokeCmd, guardrailSignerBundleCmd)
	guardrailCmd.AddCommand(guardrailSignerCmd)
	guardrailSignerRotateCmd.Flags().StringVar(&guardrailSignerAdd, "add", "", "New signer's .pub file from 'guardrail keygen' (required)")
	guardrailSignerRotateCmd.Flags().StringVar(&guardrailSignerLabel, "label", "", "Reviewer-readable name for the new key (no personal data)")
	_ = guardrailSignerRotateCmd.MarkFlagRequired("add")
	guardrailSignerRevokeCmd.Flags().StringVar(&guardrailSignerReason, "reason", "", "Why the key is revoked (required)")
	guardrailSignerBundleCmd.Flags().StringVar(&guardrailSignerOut, "out", "", "File to write (default stdout)")
}

// storeSignerChange reads the policy, builds the replacement with build, and
// writes it back with the revision it read.
func storeSignerChange(cmd *cobra.Command, build func(*pb.GetGuardrailPolicyResponse) (*pb.SetGuardrailPolicyRequest, error), what string) error {
	api, done, err := newGuardrailPolicyAPI()
	if err != nil {
		return err
	}
	defer done()
	cur, err := api.GetGuardrailPolicy()
	if err != nil {
		return err
	}
	req, err := build(cur)
	if err != nil {
		return err
	}
	if err := guardrailpolicy.ValidateSetRequest(req); err != nil {
		return fmt.Errorf("invalid guardrail policy: %w", err)
	}
	resp, err := api.SetGuardrailPolicy(req)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s; guardrail policy stored: revision %d, policy hash %s\n",
		what, resp.GetPolicy().GetRevision(), resp.GetPolicyHash())
	return err
}

func runGuardrailSignerRotate(cmd *cobra.Command, _ []string) error {
	pub, err := guardrail.LoadPublicKey(guardrailSignerAdd)
	if err != nil {
		return err
	}
	return storeSignerChange(cmd, func(cur *pb.GetGuardrailPolicyResponse) (*pb.SetGuardrailPolicyRequest, error) {
		return guardrailpolicy.RotateRequest(cur, pub, guardrailSignerLabel)
	}, "trusted key "+shortGuardrailHash(guardrail.KeyID(pub)))
}

func runGuardrailSignerRevoke(cmd *cobra.Command, args []string) error {
	return storeSignerChange(cmd, func(cur *pb.GetGuardrailPolicyResponse) (*pb.SetGuardrailPolicyRequest, error) {
		return guardrailpolicy.RevokeRequest(cur, args[0], guardrailSignerReason)
	}, "revoked key "+shortGuardrailHash(args[0]))
}

func runGuardrailSignerBundle(cmd *cobra.Command, _ []string) error {
	api, done, err := newGuardrailPolicyAPI()
	if err != nil {
		return err
	}
	defer done()
	cur, err := api.GetGuardrailPolicy()
	if err != nil {
		return err
	}
	if !cur.GetConfigured() {
		return fmt.Errorf("the server has no guardrail policy configured, so there is no trust bundle")
	}
	b, err := protojson.MarshalOptions{Multiline: true}.Marshal(guardrailpolicy.BundleOf(cur.GetPolicy()))
	if err != nil {
		return err
	}
	if guardrailSignerOut == "" {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	return os.WriteFile(guardrailSignerOut, append(b, '\n'), 0o600)
}

// verifyWithTrustBundle is verify's offline path under a bundle: a revoked
// key fails first, then the signer must be in the bundle.
func verifyWithTrustBundle(path string, att *pb.GuardrailAttestation, dir string, required []pb.GuardrailKind) (*pb.GuardrailTrustedSigner, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied --trust-bundle path
	if err != nil {
		return nil, err
	}
	bundle := &pb.GuardrailTrustBundle{}
	if err := protojson.Unmarshal(raw, bundle); err != nil {
		return nil, fmt.Errorf("trust bundle %s: %w", path, err)
	}
	if err := guardrailpolicy.CheckRevoked(att, bundle.GetRevoked()); err != nil {
		return nil, err
	}
	for _, s := range bundle.GetSigners() {
		if s.GetKeyId() != att.GetKeyId() {
			continue
		}
		if err := guardrail.VerifySubject(att, s.GetPublicKey(), dir); err != nil {
			return nil, err
		}
		if err := guardrail.VerifyCoverage(att, required); err != nil {
			return nil, err
		}
		return s, nil
	}
	return nil, fmt.Errorf("%w (attestation key %s is not in the trust bundle)", guardrailpolicy.ErrUntrustedSigner, shortGuardrailHash(att.GetKeyId()))
}
