// Package skills provides the built-in catalog of agent skills. A skill is a
// packaged, runnable agent: a box (a recipe id) plus a typed manifest
// (system prompt, allowed scopes, agent card, allowed peers). It mirrors
// pkg/core/recipes: the catalog ships as embedded YAML and is exposed to the
// rest of the system as strongly-typed pb.AgentSkill values.
//
// This catalog is the generic mechanism only — the reference skill is
// deliberately task-agnostic. Opinionated/domain skills (compliance, etc.)
// ship outside this repo.
package skills

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/catalogsig"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var embeddedFS embed.FS

// cardDef mirrors pb.AgentCard for YAML decoding.
type cardDef struct {
	ID               string   `yaml:"id"`
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description,omitempty"`
	Capabilities     []string `yaml:"capabilities,omitempty"`
	InputSchemaJSON  string   `yaml:"input_schema_json,omitempty"`
	OutputSchemaJSON string   `yaml:"output_schema_json,omitempty"`
}

// skillDef is the YAML shape of a skill. It converts to pb.AgentSkill via
// ToProto so the wire/API contract stays the single source of truth. Only the
// recipe_id box form is expressible in YAML; inline recipes are an API-only
// (one-off) construct.
type skillDef struct {
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description,omitempty"`
	RecipeID      string   `yaml:"recipe_id"`
	SystemPrompt  string   `yaml:"system_prompt"`
	AllowedScopes []string `yaml:"allowed_scopes"`
	AgentCard     *cardDef `yaml:"agent_card,omitempty"`
	AllowedPeers  []string `yaml:"allowed_peers,omitempty"`
	Model         string   `yaml:"model,omitempty"`
}

// ToProto converts a skillDef to its pb.AgentSkill representation.
func (s *skillDef) ToProto() *pb.AgentSkill {
	out := &pb.AgentSkill{
		Id:            s.ID,
		Name:          s.Name,
		Description:   s.Description,
		Box:           &pb.AgentSkill_RecipeId{RecipeId: s.RecipeID},
		SystemPrompt:  s.SystemPrompt,
		AllowedScopes: s.AllowedScopes,
		AllowedPeers:  s.AllowedPeers,
		Model:         s.Model,
	}
	if s.AgentCard != nil {
		out.AgentCard = &pb.AgentCard{
			Id:               s.AgentCard.ID,
			Name:             s.AgentCard.Name,
			Description:      s.AgentCard.Description,
			Capabilities:     s.AgentCard.Capabilities,
			InputSchemaJson:  s.AgentCard.InputSchemaJSON,
			OutputSchemaJson: s.AgentCard.OutputSchemaJSON,
		}
	}
	return out
}

type config struct {
	Skills []skillDef `yaml:"skills"`
}

// Manager holds the loaded skill catalog.
type Manager struct {
	skills []*pb.AgentSkill
	mu     sync.RWMutex
}

var (
	defaultManager *Manager
	once           sync.Once
)

// New creates an empty skill manager.
func New() *Manager { return &Manager{} }

// GetDefault returns the process-wide manager backed by the embedded catalog.
func GetDefault() *Manager {
	once.Do(func() {
		defaultManager = New()
		if err := defaultManager.LoadEmbedded(); err != nil {
			// Embedded data is compiled in; a failure here is a programmer
			// error, so leaving the catalog empty is the safe degradation.
			defaultManager.skills = nil
		}
	})
	return defaultManager
}

// LoadEmbedded loads the built-in skills.yaml bundled into the binary.
func (m *Manager) LoadEmbedded() error {
	data, err := embeddedFS.ReadFile("skills.yaml")
	if err != nil {
		return fmt.Errorf("read embedded skills: %w", err)
	}
	return m.LoadFromBytes(data)
}

// LoadFromBytes parses and validates a YAML skill catalog.
func (m *Manager) LoadFromBytes(data []byte) error {
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse skills YAML: %w", err)
	}

	loaded := make([]*pb.AgentSkill, 0, len(cfg.Skills))
	seen := map[string]bool{}
	for i := range cfg.Skills {
		def := &cfg.Skills[i]
		if err := validate(def); err != nil {
			return err
		}
		if seen[def.ID] {
			return fmt.Errorf("duplicate skill id: %s", def.ID)
		}
		seen[def.ID] = true
		loaded = append(loaded, def.ToProto())
	}

	m.mu.Lock()
	m.skills = loaded
	m.mu.Unlock()
	return nil
}

func validate(s *skillDef) error {
	if s.ID == "" {
		return fmt.Errorf("skill is missing required field: id")
	}
	if s.RecipeID == "" {
		return fmt.Errorf("skill %q is missing required field: recipe_id", s.ID)
	}
	if s.SystemPrompt == "" {
		return fmt.Errorf("skill %q is missing required field: system_prompt", s.ID)
	}
	// Least-privilege is enforced at the manifest level: a skill MUST declare
	// at least one scope. An empty set would mint a token with no `scopes`
	// claim, which HasScope treats as "no restriction" (backwards compat) —
	// the opposite of what a leaf skill wants. Declaring scopes makes the
	// in-box token explicitly bounded.
	if len(s.AllowedScopes) == 0 {
		return fmt.Errorf("skill %q must declare at least one allowed_scope", s.ID)
	}
	for _, sc := range s.AllowedScopes {
		if !auth.IsKnownScope(sc) {
			return fmt.Errorf("skill %q declares unknown scope %q", s.ID, sc)
		}
	}
	return nil
}

// LoadDir merges every *.yaml skill catalog in dir on top of what's already
// loaded (the embedded built-ins), so out-of-tree catalogs can register skills
// without recompiling (#620). A missing dir is not an error (no external
// catalog configured). Fails on a parse/validate error or an id that collides
// with an already-loaded skill. Catalogs are loaded unsigned; use
// LoadDirVerified to require a provenance check.
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
		return fmt.Errorf("read skills dir %q: %w", dir, err)
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
// collides with an already-loaded skill.
func (m *Manager) mergeBytes(data []byte) error {
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse skills YAML: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing := make(map[string]bool, len(m.skills))
	for _, s := range m.skills {
		existing[s.Id] = true
	}
	for i := range cfg.Skills {
		def := &cfg.Skills[i]
		if err := validate(def); err != nil {
			return err
		}
		if existing[def.ID] {
			return fmt.Errorf("duplicate skill id: %s", def.ID)
		}
		existing[def.ID] = true
		m.skills = append(m.skills, def.ToProto())
	}
	return nil
}

// List returns all loaded skills.
func (m *Manager) List() []*pb.AgentSkill {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*pb.AgentSkill, len(m.skills))
	copy(out, m.skills)
	return out
}

// Get returns a skill by ID, or an error if it does not exist.
func (m *Manager) Get(id string) (*pb.AgentSkill, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.skills {
		if s.Id == id {
			return s, nil
		}
	}
	return nil, fmt.Errorf("skill not found: %s", id)
}
