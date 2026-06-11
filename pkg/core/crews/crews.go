// Package crews provides the built-in catalog of crews. A crew is a
// collaborating set of skills bound to a task purpose, with a topology
// describing how they are wired. It mirrors pkg/core/skills and
// pkg/core/recipes: the catalog ships as embedded YAML and is exposed as
// strongly-typed pb.Crew values.
//
// This catalog is the generic mechanism only — the reference crew is
// deliberately task-agnostic. Opinionated/domain crews ship outside this repo.
package crews

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/footprintai/containarium/pkg/core/catalogsig"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var embeddedFS embed.FS

// topologyByName maps the YAML topology string to the proto enum. Keeping the
// mapping here (not a bare string) upholds the strong-typing convention.
var topologyByName = map[string]pb.CrewTopology{
	"pipeline":     pb.CrewTopology_CREW_TOPOLOGY_PIPELINE,
	"orchestrator": pb.CrewTopology_CREW_TOPOLOGY_ORCHESTRATOR,
	"freeform":     pb.CrewTopology_CREW_TOPOLOGY_FREEFORM,
}

// crewDef is the YAML shape of a crew.
type crewDef struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Topology    string   `yaml:"topology"`
	SkillIDs    []string `yaml:"skill_ids"`
}

// ToProto converts a crewDef to its pb.Crew representation.
func (c *crewDef) ToProto() *pb.Crew {
	return &pb.Crew{
		Id:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		Topology:    topologyByName[c.Topology],
		SkillIds:    c.SkillIDs,
	}
}

type config struct {
	Crews []crewDef `yaml:"crews"`
}

// Manager holds the loaded crew catalog.
type Manager struct {
	crews []*pb.Crew
	mu    sync.RWMutex
}

var (
	defaultManager *Manager
	once           sync.Once
)

// New creates an empty crew manager.
func New() *Manager { return &Manager{} }

// GetDefault returns the process-wide manager backed by the embedded catalog.
func GetDefault() *Manager {
	once.Do(func() {
		defaultManager = New()
		if err := defaultManager.LoadEmbedded(); err != nil {
			defaultManager.crews = nil
		}
	})
	return defaultManager
}

// LoadEmbedded loads the built-in crews.yaml bundled into the binary.
func (m *Manager) LoadEmbedded() error {
	data, err := embeddedFS.ReadFile("crews.yaml")
	if err != nil {
		return fmt.Errorf("read embedded crews: %w", err)
	}
	return m.LoadFromBytes(data)
}

// LoadFromBytes parses and validates a YAML crew catalog.
func (m *Manager) LoadFromBytes(data []byte) error {
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse crews YAML: %w", err)
	}

	loaded := make([]*pb.Crew, 0, len(cfg.Crews))
	seen := map[string]bool{}
	for i := range cfg.Crews {
		def := &cfg.Crews[i]
		if err := validate(def); err != nil {
			return err
		}
		if seen[def.ID] {
			return fmt.Errorf("duplicate crew id: %s", def.ID)
		}
		seen[def.ID] = true
		loaded = append(loaded, def.ToProto())
	}

	m.mu.Lock()
	m.crews = loaded
	m.mu.Unlock()
	return nil
}

func validate(c *crewDef) error {
	if c.ID == "" {
		return fmt.Errorf("crew is missing required field: id")
	}
	if _, ok := topologyByName[c.Topology]; !ok {
		return fmt.Errorf("crew %q has unknown topology %q (want pipeline|orchestrator|freeform)", c.ID, c.Topology)
	}
	if len(c.SkillIDs) < 2 {
		return fmt.Errorf("crew %q must reference at least two skills", c.ID)
	}
	return nil
}

// LoadDir merges every *.yaml crew catalog in dir on top of the embedded
// built-ins (#620). A missing dir is not an error. Fails on a parse/validate
// error or an id that collides with an already-loaded crew. (Topology vs the
// members' allowed_peers is validated at RunCrew time, against the skill
// catalog — so load external skills before external crews.) Catalogs are
// loaded unsigned; use LoadDirVerified to require a provenance check.
func (m *Manager) LoadDir(dir string) error {
	return m.LoadDirVerified(dir, nil)
}

// LoadDirVerified is LoadDir with an optional provenance check (#648). When v
// is non-nil (require-signed mode on), each *.yaml file must carry a valid
// detached ed25519 signature (foo.yaml.sig) under a trusted key, verified
// before parse/merge; a missing or bad signature fails that file's load rather
// than silently skipping it. When v is nil, behavior is identical to LoadDir.
func (m *Manager) LoadDirVerified(dir string, v *catalogsig.Verifier) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read crews dir %q: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if v != nil {
			sig, err := catalogsig.ReadDetachedSig(path)
			if err != nil {
				return fmt.Errorf("%s: %w", e.Name(), err)
			}
			if err := v.Verify(data, sig); err != nil {
				return fmt.Errorf("%s: signature verification failed: %w", e.Name(), err)
			}
		}
		if err := m.mergeBytes(data); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	return nil
}

// mergeBytes parses + validates a catalog and appends it, rejecting an id that
// collides with an already-loaded crew.
func (m *Manager) mergeBytes(data []byte) error {
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse crews YAML: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing := make(map[string]bool, len(m.crews))
	for _, c := range m.crews {
		existing[c.Id] = true
	}
	for i := range cfg.Crews {
		def := &cfg.Crews[i]
		if err := validate(def); err != nil {
			return err
		}
		if existing[def.ID] {
			return fmt.Errorf("duplicate crew id: %s", def.ID)
		}
		existing[def.ID] = true
		m.crews = append(m.crews, def.ToProto())
	}
	return nil
}

// List returns all loaded crews.
func (m *Manager) List() []*pb.Crew {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*pb.Crew, len(m.crews))
	copy(out, m.crews)
	return out
}

// Get returns a crew by ID, or an error if it does not exist.
func (m *Manager) Get(id string) (*pb.Crew, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.crews {
		if c.Id == id {
			return c, nil
		}
	}
	return nil, fmt.Errorf("crew not found: %s", id)
}
