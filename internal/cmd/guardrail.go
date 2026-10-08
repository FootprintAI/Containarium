package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium guardrail` — run a detection engine over a directory of
// text, redact what it flags, re-scan the result as the gate, and sign an
// attestation a consumer verifies before using the data
// (docs/architecture/guardrail.md). This is the data owner's side of a trust
// boundary: scanning, redaction and signing run on the machine the CLI runs
// on, and no dataset content ever leaves it. Since #2368 that is no longer
// "nothing talks to the daemon": `apply` and `verify` READ the server-side
// guardrail policy when a daemon is reachable (guardrail_server.go says
// exactly what is sent, which is only that read), and `guardrail policy`
// (guardrail_policy.go) reads or sets it. The engine is a separate process reached over
// gRPC (--engine); with no --engine the in-tree reference rules engine
// runs, which is a handful of regular expressions for proving the flow,
// not a detector anyone should ship data on.
var guardrailCmd = &cobra.Command{
	Use:   "guardrail",
	Short: "Scan, redact, gate and attest a dataset before it leaves your side",
}

var (
	guardrailEngineAddr   string
	guardrailKinds        []string
	guardrailJSON         bool
	guardrailOut          string
	guardrailPolicyFile   string
	guardrailVaultFile    string
	guardrailRedactKey    string
	guardrailSignKey      string
	guardrailAttestFile   string
	guardrailPublicKey    string
	guardrailRequireKinds []string
	guardrailKeygenPrefix string
)

var guardrailScanCmd = &cobra.Command{
	Use:   "scan <dir>",
	Short: "Report what the engine finds in a directory, without changing anything",
	Long: `Scan every regular file under <dir> and print findings per kind and
type. Nothing is written. --json prints each finding with its unit and
code-point offsets — never the flagged text itself, so the output is safe
to keep in a log.

Examples:
  containarium guardrail scan ./export
  containarium guardrail scan ./export --engine 127.0.0.1:9090 --kind pii --json`,
	Args: cobra.ExactArgs(1),
	RunE: runGuardrailScan,
}

var guardrailApplyCmd = &cobra.Command{
	Use:   "apply <dir>",
	Short: "Redact findings into --out, re-scan as the gate, and write an attestation",
	Long: `Scan <dir>, replace every finding with a stable placeholder token,
write the result under --out, scan --out again, and decide: PASS when the
re-scan is within policy and nothing was unscannable, FAIL otherwise (exit
status 1). The attestation is written either way so a FAIL is on record.

The vault (token -> original) and the redaction key are written beside
--out, never inside it; they are the only way back and stay with you.
With --sign-key the attestation is signed so a consumer can verify it with
the matching .pub (see 'guardrail keygen' and 'guardrail verify').

Policy: when a daemon is reachable (--server) and holds a guardrail policy,
apply runs under the server's policy, and --policy is refused unless it is
the same policy (same hash). Only the policy is read from the daemon; no
dataset content is sent. With no reachable daemon, or no server policy,
apply runs under --policy (or the default) and says on stderr that the
result is NOT server-attested.

Examples:
  containarium guardrail keygen --out ./tenant
  containarium guardrail apply ./export --out ./export-clean --sign-key ./tenant.key
  containarium guardrail apply ./export --out ./clean --engine 127.0.0.1:9090 --policy ./policy.json`,
	Args: cobra.ExactArgs(1),
	RunE: runGuardrailApply,
}

var guardrailVerifyCmd = &cobra.Command{
	Use:   "verify <dir>",
	Short: "Check a directory against its attestation before using the data",
	Long: `Verify the attestation's signature, recompute the digest of <dir> and
require it to match, and require the verdict to be PASS. Exit status 0 only
when all hold. This is what a training job or a CI step runs first.

When a daemon is reachable (--server) and holds a guardrail policy, the
check is server-trusted: the attestation's policy hash must equal the
server policy's, and its signer must be one of the server's trusted signers
(--public-key is then ignored). Only the policy is read from the daemon;
nothing is sent. Offline (no reachable daemon, or no server policy),
--public-key is required and the result is reported as NOT server-trusted.

Examples:
  containarium guardrail verify ./export-clean --attestation ./export-clean.attestation.json --server <host>:50051
  containarium guardrail verify ./export-clean --attestation ./export-clean.attestation.json --public-key ./tenant.pub`,
	Args: cobra.ExactArgs(1),
	RunE: runGuardrailVerify,
}

var guardrailKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an ed25519 attestation signing key pair",
	Long: `Write <prefix>.key (private, 0600 — keep it on the side that runs
'guardrail apply') and <prefix>.pub (give it to whoever verifies).

Example:
  containarium guardrail keygen --out ./tenant`,
	Args: cobra.NoArgs,
	RunE: runGuardrailKeygen,
}

func init() {
	guardrailCmd.AddCommand(guardrailScanCmd, guardrailApplyCmd, guardrailVerifyCmd, guardrailKeygenCmd)
	rootCmd.AddCommand(guardrailCmd)

	for _, c := range []*cobra.Command{guardrailScanCmd, guardrailApplyCmd} {
		c.Flags().StringVar(&guardrailEngineAddr, "engine", "", "GuardrailEngineService gRPC address (host:port). Empty = the in-tree reference rules engine")
	}
	// --kind is a scan-only diagnostic. apply derives the kinds from its
	// policy (#2362): an empty list would mean "whatever the engine has
	// enabled", and a policy that says REDACT SECRET against an engine that
	// cannot scan secrets must fail, not attest a PASS that never looked.
	guardrailScanCmd.Flags().StringSliceVar(&guardrailKinds, "kind", nil, "Kinds to scan for: pii, secret. Empty = every kind the engine supports")
	guardrailScanCmd.Flags().BoolVar(&guardrailJSON, "json", false, "Print findings as JSON (offsets and types only, never the text)")

	guardrailApplyCmd.Flags().StringVar(&guardrailOut, "out", "", "Directory to write the redacted copy to (required)")
	_ = guardrailApplyCmd.MarkFlagRequired("out")
	guardrailApplyCmd.Flags().StringVar(&guardrailPolicyFile, "policy", "", "GuardrailPolicy as JSON. Default: redact every kind, tolerate no residual")
	guardrailApplyCmd.Flags().StringVar(&guardrailVaultFile, "vault", "", "Where to write token -> original (default <out>.vault.json)")
	guardrailApplyCmd.Flags().StringVar(&guardrailRedactKey, "redaction-key", "", "32-byte hex key that makes tokens stable across runs; generated at <out>.redaction.key if missing")
	guardrailApplyCmd.Flags().StringVar(&guardrailSignKey, "sign-key", "", "ed25519 private key file from 'guardrail keygen' to sign the attestation")
	guardrailApplyCmd.Flags().StringVar(&guardrailAttestFile, "attestation", "", "Where to write the attestation (default <out>.attestation.json)")

	guardrailVerifyCmd.Flags().StringVar(&guardrailAttestFile, "attestation", "", "Attestation JSON written by 'guardrail apply' (required)")
	guardrailVerifyCmd.Flags().StringVar(&guardrailPublicKey, "public-key", "", "Signer's .pub file (required offline; ignored when a server policy is in force)")
	guardrailVerifyCmd.Flags().StringSliceVar(&guardrailRequireKinds, "require-kind", nil, "Kinds the attestation must have scanned for (pii, secret); a PASS that never looked for one is refused")
	_ = guardrailVerifyCmd.MarkFlagRequired("attestation")

	guardrailKeygenCmd.Flags().StringVar(&guardrailKeygenPrefix, "out", "", "Path prefix for <prefix>.key and <prefix>.pub (required)")
	_ = guardrailKeygenCmd.MarkFlagRequired("out")
}

// guardrailEngine picks the engine from --engine. The gRPC path is plain
// text: the engine is a local plug point on the data owner's own host, and
// a remote engine would mean shipping the raw text somewhere — which is
// the thing this command exists to avoid.
func guardrailEngine(cmd *cobra.Command) (guardrail.Engine, func(), error) {
	if guardrailEngineAddr == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "guardrail: using the reference rules engine (regular expressions only — for proving the flow, not for production data)")
		return guardrail.RulesEngine{}, func() {}, nil
	}
	conn, err := grpc.NewClient(guardrailEngineAddr, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("engine %s: %w", guardrailEngineAddr, err)
	}
	return guardrail.NewGRPCEngine(conn), func() { _ = conn.Close() }, nil
}

// parseGuardrailKinds turns a --kind / --require-kind value list into kinds.
func parseGuardrailKinds(flag string, raw []string) ([]pb.GuardrailKind, error) {
	var out []pb.GuardrailKind
	for _, k := range raw {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "pii":
			out = append(out, pb.GuardrailKind_GUARDRAIL_KIND_PII)
		case "secret":
			out = append(out, pb.GuardrailKind_GUARDRAIL_KIND_SECRET)
		default:
			return nil, fmt.Errorf("--%s %q: want pii or secret", flag, k)
		}
	}
	return out, nil
}

func guardrailKindsFromFlag() ([]pb.GuardrailKind, error) {
	return parseGuardrailKinds("kind", guardrailKinds)
}

func kindNames(kinds []pb.GuardrailKind) string {
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		names = append(names, strings.ToLower(strings.TrimPrefix(k.String(), "GUARDRAIL_KIND_")))
	}
	return strings.Join(names, ",")
}

func runGuardrailScan(cmd *cobra.Command, args []string) error {
	engine, closeEngine, err := guardrailEngine(cmd)
	if err != nil {
		return err
	}
	defer closeEngine()
	kinds, err := guardrailKindsFromFlag()
	if err != nil {
		return err
	}
	units, gaps, err := guardrail.LoadUnits(args[0])
	if err != nil {
		return err
	}
	resp, err := engine.Scan(cmd.Context(), &pb.GuardrailScanRequest{Units: units, Kinds: kinds})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	resp.Gaps = append(resp.Gaps, gaps...)
	if guardrailJSON {
		b, err := protojson.MarshalOptions{Multiline: true}.Marshal(resp)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return nil
	}
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "engine: %s %s\n", resp.GetEngineId(), resp.GetEngineVersion())
	fmt.Fprintf(w, "units: %d scanned, %d gap(s)\n", len(units), len(resp.GetGaps()))
	printGuardrailCounts(w, resp.GetFindings())
	return nil
}

func printGuardrailCounts(w interface{ Write([]byte) (int, error) }, findings []*pb.GuardrailFinding) {
	counts := map[string]int{}
	for _, f := range findings {
		counts[strings.TrimPrefix(f.GetKind().String(), "GUARDRAIL_KIND_")+" "+f.GetType()]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "findings: %d\n", len(findings))
	for _, k := range keys {
		fmt.Fprintf(w, "  %-32s %d\n", k, counts[k])
	}
}

func runGuardrailApply(cmd *cobra.Command, args []string) error {
	in := args[0]
	out := guardrailOut
	if guardrailVaultFile == "" {
		guardrailVaultFile = strings.TrimRight(out, "/") + ".vault.json"
	}
	if guardrailAttestFile == "" {
		guardrailAttestFile = strings.TrimRight(out, "/") + ".attestation.json"
	}
	if guardrailRedactKey == "" {
		guardrailRedactKey = strings.TrimRight(out, "/") + ".redaction.key"
	}

	// The policy is settled before anything is written, so a refused
	// --policy leaves nothing behind.
	policy, server, err := resolveApplyPolicy(cmd)
	if err != nil {
		return err
	}
	engine, closeEngine, err := guardrailEngine(cmd)
	if err != nil {
		return err
	}
	defer closeEngine()
	// Exactly the kinds the policy covers, never empty (#2362): an engine
	// that cannot scan one of them must fail this run, not pass it.
	kinds := guardrail.KindsFor(policy)
	key, err := loadOrCreateRedactionKey(cmd, guardrailRedactKey)
	if err != nil {
		return err
	}
	var signer func(*pb.GuardrailAttestation) error
	if guardrailSignKey != "" {
		priv, err := guardrail.LoadSigningKey(guardrailSignKey)
		if err != nil {
			return err
		}
		signer = func(att *pb.GuardrailAttestation) error { return guardrail.Sign(att, priv) }
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	units, loadGaps, err := guardrail.LoadUnits(in)
	if err != nil {
		return err
	}
	first, err := engine.Scan(ctx, &pb.GuardrailScanRequest{Units: units, Kinds: kinds})
	if err != nil {
		return fmt.Errorf("scan for %s: %w — nothing written; the engine must cover every kind the policy names", kindNames(kinds), err)
	}
	red, err := guardrail.Redact(units, first.GetFindings(), policy, key)
	if err != nil {
		return err
	}
	if err := guardrail.WriteUnits(out, red.Wiped); err != nil {
		return err
	}
	if err := writeGuardrailJSON(guardrailVaultFile, red.Vault, 0o600); err != nil {
		return err
	}

	wipedUnits := make([]*pb.GuardrailTextUnit, 0, len(red.Wiped))
	for id, text := range red.Wiped {
		wipedUnits = append(wipedUnits, &pb.GuardrailTextUnit{UnitId: id, Text: text})
	}
	sort.Slice(wipedUnits, func(i, j int) bool { return wipedUnits[i].UnitId < wipedUnits[j].UnitId })
	second, err := engine.Scan(ctx, &pb.GuardrailScanRequest{Units: wipedUnits, Kinds: kinds})
	if err != nil {
		return fmt.Errorf("re-scan: %w", err)
	}
	// A file the loader could not decode was never redacted and is not in
	// --out, but it is part of what the caller asked to clean: a gap.
	second.Gaps = append(second.Gaps, loadGaps...)
	gate := guardrail.Gate(second, red.Wiped, policy, red.Blocked)

	digest, err := guardrail.SubjectDigest(out)
	if err != nil {
		return err
	}
	policyHash, err := guardrail.PolicyHash(policy)
	if err != nil {
		return err
	}
	att := &pb.GuardrailAttestation{
		SubjectSha256: digest,
		EngineId:      first.GetEngineId(),
		EngineVersion: first.GetEngineVersion(),
		PolicyHash:    policyHash,
		Found:         kindCounts(red.Found),
		Residual:      kindCounts(gate.Residual),
		CoverageGaps:  gate.Gaps,
		Verdict:       gate.Verdict,
		AttestedAt:    timestamppb.New(time.Now().UTC()),
		KindsScanned:  kinds,
	}
	if signer != nil {
		if err := signer(att); err != nil {
			return err
		}
	}
	attJSON, err := protojson.MarshalOptions{Multiline: true}.Marshal(att)
	if err != nil {
		return err
	}
	// #nosec G306 -- the attestation ships with the data and carries counts and hashes, never text
	if err := os.WriteFile(guardrailAttestFile, append(attJSON, '\n'), 0o644); err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "engine: %s %s  kinds scanned: %s\n", att.EngineId, att.EngineVersion, kindNames(kinds))
	fmt.Fprintf(w, "units: %d, found %d, redacted into %s\n", len(units), len(first.GetFindings()), out)
	fmt.Fprintf(w, "re-scan: %d residual judged, %d inside placeholders ignored, %d gap(s)\n", sumCounts(gate.Residual), gate.InPlaceholder, gate.Gaps)
	fmt.Fprintf(w, "vault: %s (%d tokens)  attestation: %s  signed: %v\n", guardrailVaultFile, len(red.Vault), guardrailAttestFile, signer != nil)
	if server.policy != nil {
		fmt.Fprintf(w, "policy: server policy revision %d (hash %s)\n", server.policy.GetRevision(), shortGuardrailHash(server.hash))
	} else {
		fmt.Fprintf(w, "policy: local (hash %s), NOT server-attested\n", shortGuardrailHash(policyHash))
	}
	fmt.Fprintf(w, "verdict: %s\n", strings.TrimPrefix(gate.Verdict.String(), "GUARDRAIL_VERDICT_"))
	if gate.Verdict != pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS {
		return errors.New("guardrail gate FAILED: " + strings.Join(gate.Reasons, "; "))
	}
	return nil
}

func runGuardrailVerify(cmd *cobra.Command, args []string) error {
	b, err := os.ReadFile(guardrailAttestFile) // #nosec G304 -- operator-supplied --attestation path; CLI runs as the operator's UID
	if err != nil {
		return err
	}
	att := &pb.GuardrailAttestation{}
	if err := protojson.Unmarshal(b, att); err != nil {
		return fmt.Errorf("attestation %s: %w", guardrailAttestFile, err)
	}
	required, err := parseGuardrailKinds("require-kind", guardrailRequireKinds)
	if err != nil {
		return err
	}
	server, err := fetchGuardrailServerView()
	if err != nil {
		return err
	}
	verified := fmt.Sprintf("verified: %s is the subject attested PASS by %s %s (kinds scanned: %s; key %s) at %s",
		args[0], att.GetEngineId(), att.GetEngineVersion(), kindNames(att.GetKindsScanned()), shortGuardrailHash(att.GetKeyId()), att.GetAttestedAt().AsTime().Format(time.RFC3339))

	// With a server policy, the server decides: its policy hash and its
	// trusted signers, never a key the caller hands in.
	if server.policy != nil {
		if guardrailPublicKey != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), "guardrail: --public-key ignored; the server's trusted signers decide who may sign")
		}
		signer, err := guardrailpolicy.VerifyAttestation(att, server.policy, args[0], required)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s; server-trusted (policy revision %d, signer %q)\n", verified, server.policy.GetRevision(), signer.GetLabel())
		return nil
	}

	if guardrailPublicKey == "" {
		return fmt.Errorf("%s: offline verify needs --public-key", server.localReason)
	}
	pub, err := guardrail.LoadPublicKey(guardrailPublicKey)
	if err != nil {
		return err
	}
	if err := guardrail.VerifySubject(att, pub, args[0]); err != nil {
		return err
	}
	if err := guardrail.VerifyCoverage(att, required); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s; NOT server-trusted (%s; checked against --public-key only)\n", verified, server.localReason)
	return nil
}

// resolveApplyPolicy picks the policy apply runs under. With a server policy
// in force it is the server's, and --policy is refused unless it hashes to
// the server's: a local file can no longer weaken the gate silently. In
// local mode it is --policy, or the default, and stderr says the result is
// not server-attested.
func resolveApplyPolicy(cmd *cobra.Command) (*pb.GuardrailPolicy, *guardrailServerView, error) {
	var local *pb.GuardrailPolicy
	if guardrailPolicyFile != "" {
		b, err := os.ReadFile(guardrailPolicyFile) // #nosec G304 -- operator-supplied --policy path; CLI runs as the operator's UID
		if err != nil {
			return nil, nil, err
		}
		local = &pb.GuardrailPolicy{}
		if err := protojson.Unmarshal(b, local); err != nil {
			return nil, nil, fmt.Errorf("--policy %s: %w", guardrailPolicyFile, err)
		}
	}
	server, err := fetchGuardrailServerView()
	if err != nil {
		return nil, nil, err
	}
	if server.policy == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "guardrail: %s; running under the local policy. This result is NOT server-attested.\n", server.localReason)
		if local == nil {
			local = guardrail.DefaultPolicy()
		}
		return local, server, nil
	}
	if local != nil {
		h, err := guardrail.PolicyHash(local)
		if err != nil {
			return nil, nil, err
		}
		if h != server.hash {
			return nil, nil, fmt.Errorf("--policy %s (hash %s) does not match the server guardrail policy (revision %d, hash %s); omit --policy to run under the server's",
				guardrailPolicyFile, shortGuardrailHash(h), server.policy.GetRevision(), shortGuardrailHash(server.hash))
		}
	}
	return server.policy.GetPolicy(), server, nil
}

func runGuardrailKeygen(cmd *cobra.Command, _ []string) error {
	pub, err := guardrail.GenerateKeyFiles(guardrailKeygenPrefix)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s.key (private, keep here) and %s.pub (share with verifiers); key id %s\n",
		guardrailKeygenPrefix, guardrailKeygenPrefix, guardrail.KeyID(pub)[:12])
	return nil
}

// loadOrCreateRedactionKey reads a 32-byte hex key or mints one at path,
// 0600, and says so: the key is what makes tokens stable across runs, so
// losing it means the next run tokenizes the same values differently.
func loadOrCreateRedactionKey(cmd *cobra.Command, path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-supplied --redaction-key path; CLI runs as the operator's UID
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("--redaction-key %s: want 32 bytes as hex", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "guardrail: new redaction key written to %s — keep it with the vault\n", path)
	return key, nil
}

func writeGuardrailJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), mode)
}

func kindCounts(m map[pb.GuardrailKind]int64) []*pb.GuardrailKindCount {
	out := make([]*pb.GuardrailKindCount, 0, len(m))
	for k, n := range m {
		out = append(out, &pb.GuardrailKindCount{Kind: k, Findings: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

func sumCounts(m map[pb.GuardrailKind]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}
