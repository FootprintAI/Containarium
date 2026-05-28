// Package recipes provides the built-in catalog of declarative GPU/app
// recipes. A recipe defines a workload (image, ports, volumes, parameters,
// post-start commands) that the daemon provisions as a new dedicated
// container. It mirrors pkg/core/stacks: the catalog ships as embedded YAML
// and is exposed to the rest of the system as strongly-typed pb.Recipe values.
package recipes

import (
	"embed"
	"fmt"
	"strings"
	"sync"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var embeddedFS embed.FS

// resourcesDef mirrors pb.RecipeResources for YAML decoding.
type resourcesDef struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
	Disk   string `yaml:"disk"`
}

// portDef mirrors pb.RecipePort for YAML decoding.
type portDef struct {
	ContainerPort int32  `yaml:"container_port"`
	Subdomain     string `yaml:"subdomain"`
}

// volumeDef mirrors pb.RecipeVolume for YAML decoding.
type volumeDef struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// paramDef mirrors pb.RecipeParam for YAML decoding.
type paramDef struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Description string `yaml:"description,omitempty"`
	Type        string `yaml:"type"`
	Default     string `yaml:"default,omitempty"`
	Required    bool   `yaml:"required,omitempty"`
}

// recipeDef is the YAML shape of a recipe. It converts to pb.Recipe via
// ToProto so the wire/API contract stays the single source of truth.
type recipeDef struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Image       string            `yaml:"image"`
	RequiresGPU bool              `yaml:"requires_gpu,omitempty"`
	Resources   *resourcesDef     `yaml:"resources,omitempty"`
	Ports       []portDef         `yaml:"ports,omitempty"`
	Volumes     []volumeDef       `yaml:"volumes,omitempty"`
	Env         map[string]string `yaml:"env,omitempty"`
	Parameters  []paramDef        `yaml:"parameters,omitempty"`
	PostStart   []string          `yaml:"post_start,omitempty"`
}

// ToProto converts a recipeDef to its pb.Recipe representation.
func (r *recipeDef) ToProto() *pb.Recipe {
	out := &pb.Recipe{
		Id:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Image:       r.Image,
		RequiresGpu: r.RequiresGPU,
		Env:         r.Env,
		PostStart:   r.PostStart,
	}
	if r.Resources != nil {
		out.Resources = &pb.RecipeResources{
			Cpu:    r.Resources.CPU,
			Memory: r.Resources.Memory,
			Disk:   r.Resources.Disk,
		}
	}
	for _, p := range r.Ports {
		out.Ports = append(out.Ports, &pb.RecipePort{
			ContainerPort: p.ContainerPort,
			Subdomain:     p.Subdomain,
		})
	}
	for _, v := range r.Volumes {
		out.Volumes = append(out.Volumes, &pb.RecipeVolume{
			Name: v.Name,
			Path: v.Path,
		})
	}
	for _, p := range r.Parameters {
		out.Parameters = append(out.Parameters, &pb.RecipeParam{
			Name:        p.Name,
			Label:       p.Label,
			Description: p.Description,
			Type:        p.Type,
			Default:     p.Default,
			Required:    p.Required,
		})
	}
	return out
}

type config struct {
	Recipes []recipeDef `yaml:"recipes"`
}

// Manager holds the loaded recipe catalog.
type Manager struct {
	recipes []*pb.Recipe
	mu      sync.RWMutex
}

var (
	defaultManager *Manager
	once           sync.Once
)

// New creates an empty recipe manager.
func New() *Manager { return &Manager{} }

// GetDefault returns the process-wide manager backed by the embedded catalog.
func GetDefault() *Manager {
	once.Do(func() {
		defaultManager = New()
		if err := defaultManager.LoadEmbedded(); err != nil {
			// Embedded data is compiled in; a failure here is a programmer
			// error, so leaving the catalog empty is the safe degradation.
			defaultManager.recipes = nil
		}
	})
	return defaultManager
}

// LoadEmbedded loads the built-in recipes.yaml bundled into the binary.
func (m *Manager) LoadEmbedded() error {
	data, err := embeddedFS.ReadFile("recipes.yaml")
	if err != nil {
		return fmt.Errorf("read embedded recipes: %w", err)
	}
	return m.LoadFromBytes(data)
}

// LoadFromBytes parses and validates a YAML recipe catalog.
func (m *Manager) LoadFromBytes(data []byte) error {
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse recipes YAML: %w", err)
	}

	loaded := make([]*pb.Recipe, 0, len(cfg.Recipes))
	seen := map[string]bool{}
	for i := range cfg.Recipes {
		def := &cfg.Recipes[i]
		if err := validate(def); err != nil {
			return err
		}
		if seen[def.ID] {
			return fmt.Errorf("duplicate recipe id: %s", def.ID)
		}
		seen[def.ID] = true
		loaded = append(loaded, def.ToProto())
	}

	m.mu.Lock()
	m.recipes = loaded
	m.mu.Unlock()
	return nil
}

func validate(r *recipeDef) error {
	if r.ID == "" {
		return fmt.Errorf("recipe is missing required field: id")
	}
	if r.Image == "" {
		return fmt.Errorf("recipe %q is missing required field: image", r.ID)
	}
	for _, p := range r.Ports {
		if p.ContainerPort <= 0 || p.ContainerPort > 65535 {
			return fmt.Errorf("recipe %q has invalid container_port: %d", r.ID, p.ContainerPort)
		}
	}
	return nil
}

// List returns all loaded recipes.
func (m *Manager) List() []*pb.Recipe {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*pb.Recipe, len(m.recipes))
	copy(out, m.recipes)
	return out
}

// Get returns a recipe by ID, or an error if it does not exist.
func (m *Manager) Get(id string) (*pb.Recipe, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.recipes {
		if r.Id == id {
			return r, nil
		}
	}
	return nil, fmt.Errorf("recipe not found: %s", id)
}

// ResolveParameters merges deployer-supplied values over the recipe's
// declared parameter defaults and enforces required parameters. The returned
// map is keyed by parameter name. Unknown keys in overrides are ignored.
func ResolveParameters(r *pb.Recipe, overrides map[string]string) (map[string]string, error) {
	resolved := map[string]string{}
	for _, p := range r.Parameters {
		val := p.Default
		if ov, ok := overrides[p.Name]; ok && ov != "" {
			val = ov
		}
		if p.Required && val == "" {
			return nil, fmt.Errorf("recipe %q requires parameter %q", r.Id, p.Name)
		}
		resolved[p.Name] = val
	}
	return resolved, nil
}

// ParamEnvName returns the environment variable name a post_start command sees
// for a given parameter (CONTAINARIUM_PARAM_<UPPER>).
func ParamEnvName(name string) string {
	return "CONTAINARIUM_PARAM_" + strings.ToUpper(name)
}
