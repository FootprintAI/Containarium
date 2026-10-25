package crews

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestLoadDirMergesCrews(t *testing.T) {
	m := New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ext.yaml"), []byte(`
crews:
  - id: ext-crew
    topology: freeform
    skill_ids: [a, b]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	c, err := m.Get("ext-crew")
	if err != nil {
		t.Fatalf("external crew not merged: %v", err)
	}
	if c.Topology != pb.CrewTopology_CREW_TOPOLOGY_FREEFORM {
		t.Errorf("topology = %v", c.Topology)
	}
	// missing dir is a no-op
	if err := m.LoadDir(filepath.Join(dir, "nope")); err != nil {
		t.Errorf("missing dir should be a no-op, got %v", err)
	}
}

// TestLoadRoles is #2799: a crew's roles are parsed into the typed CrewRole
// enum, one per member, in member order.
func TestLoadRoles(t *testing.T) {
	m := New()
	if err := m.LoadFromBytes([]byte(`
crews:
  - id: c
    topology: pipeline
    skill_ids: [a, b, c]
    roles: [coder, reviewer, pack_producer]
  - id: plain
    topology: pipeline
    skill_ids: [a, b]
`)); err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	c, _ := m.Get("c")
	want := []pb.CrewRole{pb.CrewRole_CREW_ROLE_CODER, pb.CrewRole_CREW_ROLE_REVIEWER, pb.CrewRole_CREW_ROLE_PACK_PRODUCER}
	if len(c.GetRoles()) != len(want) {
		t.Fatalf("roles = %v, want %v", c.GetRoles(), want)
	}
	for i := range want {
		if c.GetRoles()[i] != want[i] {
			t.Errorf("roles[%d] = %v, want %v", i, c.GetRoles()[i], want[i])
		}
	}
	if plain, _ := m.Get("plain"); len(plain.GetRoles()) != 0 {
		t.Errorf("a crew without roles got %v", plain.GetRoles())
	}
}

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

func TestEmbeddedCatalogHasFreeformCrew(t *testing.T) {
	m := GetDefault()
	fc, err := m.Get("freeform-crew")
	if err != nil {
		t.Fatalf("freeform-crew reference crew missing: %v", err)
	}
	if fc.Topology != pb.CrewTopology_CREW_TOPOLOGY_FREEFORM {
		t.Errorf("freeform-crew topology = %v, want FREEFORM", fc.Topology)
	}
	if len(fc.SkillIds) < 2 {
		t.Errorf("freeform-crew should reference >=2 skills, got %v", fc.SkillIds)
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
		"unknown role": `
crews:
  - id: c
    topology: pipeline
    skill_ids: [a, b]
    roles: [coder, tester]
`,
		"role count differs from members": `
crews:
  - id: c
    topology: pipeline
    skill_ids: [a, b, c]
    roles: [coder, reviewer]
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
