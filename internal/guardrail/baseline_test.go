package guardrail

import (
	"reflect"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Every key below is synthetic: built from fixed filler, never a real key.
var (
	fakePEMHeader  = "-----BEGIN " + "RSA PRIVATE KEY-----"
	fakeAWSKeyID   = "AKIA" + "FAKEFAKEFAKEFAKE"
	fakeGoogleKey  = "AIza" + strings.Repeat("F", 35)
	fakeAzureKey   = "AccountKey=" + strings.Repeat("A", 86) + "=="
	fakeOpenSSHKey = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
)

func TestScanBaseline_Rules(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []BaselineDetection
	}{
		{"clean text", "nothing to see; -----BEGIN PUBLIC KEY----- is not secret", nil},
		{"pem rsa header", "here:\n" + fakePEMHeader + "\nMIIFAKE",
			[]BaselineDetection{{RuleID: BaselineRulePEMPrivateKey, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 1}}},
		{"pem openssh header", fakeOpenSSHKey,
			[]BaselineDetection{{RuleID: BaselineRulePEMPrivateKey, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 1}}},
		{"bare pem header", "-----BEGIN " + "PRIVATE KEY-----",
			[]BaselineDetection{{RuleID: BaselineRulePEMPrivateKey, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 1}}},
		{"aws access key id twice", "id " + fakeAWSKeyID + " and " + fakeAWSKeyID,
			[]BaselineDetection{{RuleID: BaselineRuleAWSAccessKeyID, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 2}}},
		{"google api key", "key=" + fakeGoogleKey,
			[]BaselineDetection{{RuleID: BaselineRuleGoogleAPIKey, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 1}}},
		{"azure storage key", "DefaultEndpointsProtocol=https;" + fakeAzureKey,
			[]BaselineDetection{{RuleID: BaselineRuleAzureStorageKey, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 1}}},
		{"two rules, table order", fakeAWSKeyID + " " + fakePEMHeader,
			[]BaselineDetection{
				{RuleID: BaselineRulePEMPrivateKey, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 1},
				{RuleID: BaselineRuleAWSAccessKeyID, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 1},
			}},
		// Out of the baseline on purpose (Q4: PEM headers and cloud-key shapes only).
		{"pii is not baseline", "mail a@example.com, card 4111 1111 1111 1111", nil},
		{"short AKIA is not a key id", "AKIA123", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanBaseline([]*pb.GuardrailTextUnit{{UnitId: "u", Text: tc.text}})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ScanBaseline = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Matches are summed per rule across units, so one response gives one
// detection per rule however its text was split.
func TestScanBaseline_SumsAcrossUnits(t *testing.T) {
	got := ScanBaseline([]*pb.GuardrailTextUnit{
		{UnitId: "text/0", Text: fakeAWSKeyID},
		{UnitId: "tool/0/0", Text: `{"k":"` + fakeAWSKeyID + `"}`},
	})
	want := []BaselineDetection{{RuleID: BaselineRuleAWSAccessKeyID, Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Matches: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScanBaseline = %+v, want %+v", got, want)
	}
}

// The baseline is its own table: stable ids, unique, and the set is exactly
// the accepted one. Widening it is a reviewed change to this test.
func TestBaselineRules_StableIDs(t *testing.T) {
	var ids []BaselineRuleID
	for _, r := range BaselineRules() {
		ids = append(ids, r.ID)
		if r.Kind != pb.GuardrailKind_GUARDRAIL_KIND_SECRET {
			t.Errorf("rule %s kind = %v, want SECRET", r.ID, r.Kind)
		}
	}
	want := []BaselineRuleID{"baseline.pem_private_key", "baseline.aws_access_key_id", "baseline.google_api_key", "baseline.azure_storage_account_key"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("baseline rule ids = %v, want %v", ids, want)
	}
}

// A detection carries counts and ids only; no field can hold matched text.
func TestBaselineDetection_NoTextBearingField(t *testing.T) {
	typ := reflect.TypeOf(BaselineDetection{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type == reflect.TypeOf("") || f.Type.Kind() == reflect.Slice {
			t.Errorf("BaselineDetection.%s is a plain string; only typed ids and counts are allowed", f.Name)
		}
	}
}

// The literal prefilter only skips text that cannot match: ScanBaseline must
// find exactly what the bare patterns find, on hits, near-misses and text
// with the literal but no match.
func TestScanBaseline_PrefilterKeepsMatches(t *testing.T) {
	corpus := []string{
		fakePEMHeader, fakeOpenSSHKey, "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----", "PRIVATE KEY but no header",
		fakeAWSKeyID, "ASIA" + "FAKEFAKEFAKEFAKE", "xAKIAFAKEFAKEFAKEFAKE", "AKIA too short", "AKIA" + "FAKEFAKEFAKEFAKEX",
		fakeGoogleKey, "AIza short", "_" + fakeGoogleKey,
		fakeAzureKey, "AccountKey=short==",
		"no literal at all", strings.Repeat("filler ", 100) + fakeAWSKeyID + " " + fakePEMHeader,
	}
	for _, text := range corpus {
		got := map[BaselineRuleID]int{}
		for _, d := range ScanBaseline([]*pb.GuardrailTextUnit{{UnitId: "u", Text: text}}) {
			got[d.RuleID] = d.Matches
		}
		for _, r := range BaselineRules() {
			if want := len(r.pattern.FindAllStringIndex(text, -1)); got[r.ID] != want {
				t.Errorf("%q: rule %s matches = %d, bare pattern finds %d", text, r.ID, got[r.ID], want)
			}
		}
	}
}

func TestBaselineAction_String(t *testing.T) {
	if s := BaselineActionLog.String(); s != "log" {
		t.Errorf("BaselineActionLog = %q, want log", s)
	}
	if s := BaselineAction(0).String(); s != "unknown" {
		t.Errorf("zero action = %q, want unknown", s)
	}
}
