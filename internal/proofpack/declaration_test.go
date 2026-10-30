package proofpack

import (
	"fmt"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestParseDeclaration(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []Step
		ok      bool
		wantErr string
	}{
		{name: "string form", in: "test: make check\n", ok: true,
			want: []Step{{Name: "test", Kind: pb.ProofPartKind_PROOF_PART_KIND_TEST, Run: "make check"}}},
		{name: "list form, kinds and default kind", ok: true,
			in: "test:\n  - {name: unit, kind: unit, run: go test ./...}\n  - {name: lint, kind: static_analysis, run: golangci-lint run}\n  - {name: misc, run: ./check.sh}\n  - {name: e2e, kind: e2e, run: make e2e}\n  - {name: it, kind: integration, run: make it}\n  - {name: sec, kind: security_scan, run: gosec ./...}\n",
			want: []Step{
				{Name: "unit", Kind: pb.ProofPartKind_PROOF_PART_KIND_UNIT, Run: "go test ./..."},
				{Name: "lint", Kind: pb.ProofPartKind_PROOF_PART_KIND_STATIC_ANALYSIS, Run: "golangci-lint run"},
				{Name: "misc", Kind: pb.ProofPartKind_PROOF_PART_KIND_TEST, Run: "./check.sh"},
				{Name: "e2e", Kind: pb.ProofPartKind_PROOF_PART_KIND_E2E, Run: "make e2e"},
				{Name: "it", Kind: pb.ProofPartKind_PROOF_PART_KIND_INTEGRATION, Run: "make it"},
				{Name: "sec", Kind: pb.ProofPartKind_PROOF_PART_KIND_SECURITY_SCAN, Run: "gosec ./..."},
			}},
		{name: "other keys only", in: "runner:\n  image: ubuntu\n", ok: false},
		{name: "empty file", in: "", ok: false},
		{name: "null test", in: "test:\n", wantErr: "test: is empty"},
		{name: "explicit null test", in: "test: null\n", wantErr: "test: is empty"},
		{name: "empty string", in: "test: \"\"\n", wantErr: "empty"},
		{name: "empty list", in: "test: []\n", wantErr: "no steps"},
		{name: "mapping", in: "test:\n  run: x\n", wantErr: "must be a command or a list"},
		{name: "unknown kind", in: "test:\n  - {name: a, kind: fuzz, run: x}\n", wantErr: "unknown kind"},
		{name: "unknown field", in: "test:\n  - {name: a, run: x, env: {A: b}}\n", wantErr: "unknown step field \"env\""},
		{name: "missing run", in: "test:\n  - {name: a}\n", wantErr: "has no run"},
		{name: "missing name", in: "test:\n  - {run: x}\n", wantErr: "must match"},
		{name: "name with spaces", in: "test:\n  - {name: go test, run: x}\n", wantErr: "must match"},
		{name: "duplicate name", in: "test:\n  - {name: a, run: x}\n  - {name: a, run: y}\n", wantErr: "used twice"},
		{name: "scalar step", in: "test:\n  - go test ./...\n", wantErr: "must be a mapping"},
		{name: "bool test", in: "test: false\n", wantErr: "line 1: test: must be a string"},
		{name: "int test", in: "test: 123\n", wantErr: "line 1: test: must be a string"},
		{name: "true test", in: "test: true\n", wantErr: "line 1: test: must be a string"},
		{name: "int step name and bool run", in: "test:\n  - {name: 123, run: true}\n", wantErr: "line 2"},
		{name: "bool step run", in: "test:\n  - {name: a, run: true}\n", wantErr: "run must be a string"},
		{name: "int step kind", in: "test:\n  - {name: a, kind: 5, run: x}\n", wantErr: "kind must be a string"},
		{name: "quoted numbers are strings", in: "test: \"123\"\n", ok: true,
			want: []Step{{Name: "test", Kind: pb.ProofPartKind_PROOF_PART_KIND_TEST, Run: "123"}}},
		{name: "bad yaml", in: "test: [\n", wantErr: DeclarationPath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok, err := ParseDeclaration([]byte(c.in))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Errorf("steps = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseDeclaration_StepLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("test:\n")
	for i := 0; i <= MaxSteps; i++ {
		fmt.Fprintf(&b, "  - {name: s%d, run: x}\n", i)
	}
	if _, _, err := ParseDeclaration([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("err = %v", err)
	}
}
