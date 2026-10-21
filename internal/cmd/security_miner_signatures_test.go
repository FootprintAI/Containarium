package cmd

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func execMinerSig(t *testing.T, build func() *cobra.Command, args ...string) (string, error) {
	t.Helper()
	cmd := build()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestMinerSignaturesList_RendersBaselineAndOperator(t *testing.T) {
	reply, _ := protojson.Marshal(&pb.ListMinerSignaturesResponse{
		BaselineVersion: "1",
		Signatures: []*pb.MinerSignature{
			{Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, Pattern: "xmrig", Label: "XMRig", Builtin: true},
			{Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV, Pattern: "--coin ", Label: "coin flag", Builtin: true},
			{Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256, Pattern: strings.Repeat("ab", 32), Label: "in-house build"},
		},
	})
	ps := &policyServer{reply: string(reply)}
	ps.start(t)
	out, err := execMinerSig(t, newMinerSignaturesListCmd)
	if err != nil {
		t.Fatal(err)
	}
	if ps.method != http.MethodGet || ps.path != "/v1/security/miner-signatures" {
		t.Errorf("request = %s %s", ps.method, ps.path)
	}
	for _, want := range []string{"Baseline version: 1", "name", "baseline", `"xmrig"`, `"--coin "`, "sha256", "operator", "in-house build"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestMinerSignaturesAdd_SendsKindEnum(t *testing.T) {
	ps := &policyServer{reply: `{"signature":{"kind":"MINER_SIGNATURE_KIND_ARGV","pattern":"--algo randomx","label":"randomx"}}`}
	ps.start(t)
	out, err := execMinerSig(t, newMinerSignaturesAddCmd, "--kind", "argv", "--label", "randomx", "--", "--algo randomx")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if ps.method != http.MethodPost || ps.path != "/v1/security/miner-signatures" {
		t.Errorf("request = %s %s", ps.method, ps.path)
	}
	var req pb.AddMinerSignatureRequest
	if err := protojson.Unmarshal(ps.body, &req); err != nil {
		t.Fatalf("body %s: %v", ps.body, err)
	}
	if req.GetSignature().GetKind() != pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV || req.GetSignature().GetPattern() != "--algo randomx" {
		t.Errorf("request = %v", &req)
	}
	if !strings.Contains(out, `Added argv "--algo randomx"`) {
		t.Errorf("output = %q", out)
	}
}

func TestMinerSignaturesAdd_RejectsUnknownKind(t *testing.T) {
	ps := &policyServer{reply: `{}`}
	ps.start(t)
	if _, err := execMinerSig(t, newMinerSignaturesAddCmd, "--kind", "md5", "abc"); err == nil || !strings.Contains(err.Error(), "allowed values") {
		t.Fatalf("err = %v, want an allowed-values error", err)
	}
	if ps.method != "" {
		t.Errorf("an invalid kind must not reach the server; got %s %s", ps.method, ps.path)
	}
}

func TestMinerSignaturesRemove_QueryCarriesKindAndPattern(t *testing.T) {
	ps := &policyServer{reply: `{}`}
	ps.start(t)
	if _, err := execMinerSig(t, newMinerSignaturesRemoveCmd, "--kind", "argv", "--", "stratum+tcp://pool x"); err != nil {
		t.Fatal(err)
	}
	if ps.method != http.MethodDelete || ps.path != "/v1/security/miner-signatures" {
		t.Errorf("request = %s %s", ps.method, ps.path)
	}
	q, _ := url.ParseQuery(ps.query)
	if q.Get("kind") != "MINER_SIGNATURE_KIND_ARGV" || q.Get("pattern") != "stratum+tcp://pool x" {
		t.Errorf("query = %q", ps.query)
	}
}

// TestParseMinerSigKind (#2768 item 5): --kind is read off the proto enum,
// so every kind the enum defines is accepted (in any case) and nothing else,
// UNSPECIFIED included; the allowed-values list comes from the enum too.
func TestParseMinerSigKind(t *testing.T) {
	for k := range pb.MinerSignatureKind_name {
		kind := pb.MinerSignatureKind(k)
		if kind == pb.MinerSignatureKind_MINER_SIGNATURE_KIND_UNSPECIFIED {
			continue
		}
		label := minerSigKindLabel(kind)
		for _, in := range []string{label, strings.ToUpper(label), " " + label + " "} {
			if got, err := parseMinerSigKind(in); err != nil || got != kind {
				t.Errorf("parseMinerSigKind(%q) = %v, %v; want %v", in, got, err, kind)
			}
		}
		if !strings.Contains(minerSigKindAllowed(), label) {
			t.Errorf("allowed values %q miss %q", minerSigKindAllowed(), label)
		}
	}
	for _, in := range []string{"", "unspecified", "UNSPECIFIED", "md5", "MINER_SIGNATURE_KIND_NAME"} {
		if _, err := parseMinerSigKind(in); err == nil {
			t.Errorf("parseMinerSigKind(%q) accepted", in)
		}
	}
	if got := minerSigKindAllowed(); got != "name, argv, sha256" {
		t.Errorf("allowed values = %q, want enum order %q", got, "name, argv, sha256")
	}
}
