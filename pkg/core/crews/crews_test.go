package crews

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	m := GetDefault()
	if len(m.List()) == 0 {
		t.Fatal("embedded crew catalog is empty")
	}
	hello, err := m.Get("hello-crew")
	if err != nil {
		t.Fatalf("hello-crew reference crew missing: %v", err)
	}
	if hello.Topology != pb.CrewTopology_CREW_TOPOLOGY_PIPELINE {
		t.Errorf("hello-crew topology = %v, want PIPELINE", hello.Topology)
	}
	if len(hello.SkillIds) < 2 {
		t.Errorf("hello-crew should reference >=2 skills, got %v", hello.SkillIds)
	}
}

func TestValidateRejectsBadCrews(t *testing.T) {
	cases := map[string]string{
		"missing id": `
crews:
  - topology: pipeline
    skill_ids: [a, b]
`,
		"unknown topology": `
crews:
  - id: c
    topology: mesh
    skill_ids: [a, b]
`,
		"too few skills": `
crews:
  - id: c
    topology: pipeline
    skill_ids: [a]
`,
		"duplicate id": `
crews:
  - id: c
    topology: pipeline
    skill_ids: [a, b]
  - id: c
    topology: freeform
    skill_ids: [a, b]
`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if err := New().LoadFromBytes([]byte(yaml)); err == nil {
				t.Errorf("expected load error for %q, got nil", name)
			}
		})
	}
}
