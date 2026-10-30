// Package proofpack generates a Proof Pack: the repository's declared test
// commands, run by the platform inside a box, with each command's exit
// status and output recorded and digested (docs/PROOF-PACK.md, #2797).
//
// The coding agent has no input into a pack. Generate runs the commands
// itself through an Execer (the daemon's Incus backend) and records what
// happened; a `tests_run` claim from the agent is never consulted.
package proofpack

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// DeclarationPath is where a repository declares its test command set,
// relative to the repository root.
const DeclarationPath = ".github/containarium.yml"

const (
	// MaxDeclarationBytes bounds the declaration file read from the box.
	MaxDeclarationBytes = 64 * 1024
	// MaxSteps bounds how many steps one declaration may list.
	MaxSteps = 32
	// fallbackStepName names the `make test` step used when nothing is
	// declared.
	fallbackStepName = "make-test"
	fallbackCommand  = "make test"
	// stringFormStepName names the single step of a `test: <command>`
	// declaration.
	stringFormStepName = "test"
)

// stepNamePattern keeps step names short and free of anything that reads
// like a command line, since the name is what a pack records instead of one.
var stepNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// kindNames maps the declaration's `kind:` values to the proto enum.
var kindNames = map[string]pb.ProofPartKind{
	"test":            pb.ProofPartKind_PROOF_PART_KIND_TEST,
	"unit":            pb.ProofPartKind_PROOF_PART_KIND_UNIT,
	"integration":     pb.ProofPartKind_PROOF_PART_KIND_INTEGRATION,
	"e2e":             pb.ProofPartKind_PROOF_PART_KIND_E2E,
	"static_analysis": pb.ProofPartKind_PROOF_PART_KIND_STATIC_ANALYSIS,
	"security_scan":   pb.ProofPartKind_PROOF_PART_KIND_SECURITY_SCAN,
}

// Step is one command to run. Run is the command line: it is executed but
// never copied into a pack.
type Step struct {
	Name string
	Kind pb.ProofPartKind
	Run  string
}

// declarationFile is the part of .github/containarium.yml this package
// reads. Other top-level keys belong to other features and are ignored.
// Test is a raw node so a present-but-null `test:` (Kind set, tag !!null)
// is told apart from an absent key (Kind 0): yaml.v3 does not call a
// custom unmarshaler for a null value.
type declarationFile struct {
	Test yaml.Node `yaml:"test"`
}

type stepYAML struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"`
	Run  string `yaml:"run"`
}

// requireStrings rejects a step field whose value is not a YAML string
// (a bool or int that yaml.v3 would coerce), naming the line.
func requireStrings(n *yaml.Node) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		v := n.Content[i+1]
		if v.Kind != yaml.ScalarNode || v.ShortTag() != "!!str" {
			return fmt.Errorf("line %d: step %s must be a string", v.Line, n.Content[i].Value)
		}
	}
	return nil
}

// parseTest reads the `test:` value: either one command line, or a list of
// {name, kind, run} steps.
func parseTest(n *yaml.Node) ([]Step, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.ShortTag() == "!!null" {
			return nil, fmt.Errorf("line %d: test: is empty", n.Line)
		}
		// `test: false` or `test: 123` is a YAML bool or int that yaml.v3
		// would quietly turn into a string; the author did not write a
		// command.
		if n.ShortTag() != "!!str" {
			return nil, fmt.Errorf("line %d: test: must be a string command, got %s", n.Line, n.ShortTag())
		}
		var run string
		if err := n.Decode(&run); err != nil {
			return nil, err
		}
		if run == "" {
			return nil, fmt.Errorf("line %d: test: is empty", n.Line)
		}
		return []Step{{Name: stringFormStepName, Kind: pb.ProofPartKind_PROOF_PART_KIND_TEST, Run: run}}, nil
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			return nil, fmt.Errorf("line %d: test: lists no steps", n.Line)
		}
		if len(n.Content) > MaxSteps {
			return nil, fmt.Errorf("line %d: test: lists %d steps, more than %d", n.Line, len(n.Content), MaxSteps)
		}
		steps := make([]Step, 0, len(n.Content))
		seen := make(map[string]bool, len(n.Content))
		for _, item := range n.Content {
			step, err := decodeStep(item)
			if err != nil {
				return nil, err
			}
			if seen[step.Name] {
				return nil, fmt.Errorf("line %d: step name %q is used twice", item.Line, step.Name)
			}
			seen[step.Name] = true
			steps = append(steps, step)
		}
		return steps, nil
	default:
		return nil, fmt.Errorf("line %d: test: must be a command or a list of steps", n.Line)
	}
}

func decodeStep(n *yaml.Node) (Step, error) {
	if n.Kind != yaml.MappingNode {
		return Step{}, fmt.Errorf("line %d: a step must be a mapping with name, kind and run", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch key := n.Content[i].Value; key {
		case "name", "kind", "run":
		default:
			return Step{}, fmt.Errorf("line %d: unknown step field %q", n.Content[i].Line, key)
		}
	}
	if err := requireStrings(n); err != nil {
		return Step{}, err
	}
	var raw stepYAML
	if err := n.Decode(&raw); err != nil {
		return Step{}, err
	}
	if !stepNamePattern.MatchString(raw.Name) {
		return Step{}, fmt.Errorf("line %d: step name %q must match %s", n.Line, raw.Name, stepNamePattern)
	}
	if raw.Run == "" {
		return Step{}, fmt.Errorf("line %d: step %q has no run", n.Line, raw.Name)
	}
	kind := pb.ProofPartKind_PROOF_PART_KIND_TEST
	if raw.Kind != "" {
		k, ok := kindNames[raw.Kind]
		if !ok {
			return Step{}, fmt.Errorf("line %d: step %q has unknown kind %q", n.Line, raw.Name, raw.Kind)
		}
		kind = k
	}
	return Step{Name: raw.Name, Kind: kind, Run: raw.Run}, nil
}

// ParseDeclaration reads the `test:` key of a .github/containarium.yml.
// ok is false only when the file has no `test:` key, in which case the
// caller falls back to `make test`; a `test:` key that is present but
// empty or malformed is an error.
func ParseDeclaration(content []byte) (steps []Step, ok bool, err error) {
	var f declarationFile
	if err := yaml.Unmarshal(content, &f); err != nil {
		return nil, false, fmt.Errorf("%s: %w", DeclarationPath, err)
	}
	if f.Test.Kind == 0 {
		return nil, false, nil
	}
	steps, err = parseTest(&f.Test)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", DeclarationPath, err)
	}
	return steps, true, nil
}

// FallbackSteps is the command set used when the repository declares none
// but has a Makefile.
func FallbackSteps() []Step {
	return []Step{{Name: fallbackStepName, Kind: pb.ProofPartKind_PROOF_PART_KIND_TEST, Run: fallbackCommand}}
}
