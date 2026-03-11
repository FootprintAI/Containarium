package stacks

import (
	"embed"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var embeddedFS embed.FS

// Stack represents a pre-configured software stack
type Stack struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Icon        string   `yaml:"icon" json:"icon"`
	PreInstall  []string `yaml:"pre_install" json:"preInstall"`
	Packages    []string `yaml:"packages" json:"packages"`
	PostInstall []string `yaml:"post_install" json:"postInstall"`
}

// Config holds the stack configuration
type Config struct {
	BaseScripts []Stack `yaml:"base_scripts" json:"baseScripts"`
	Stacks      []Stack `yaml:"stacks" json:"stacks"`
}

// Manager manages stack definitions
type Manager struct {
	config Config
	mu     sync.RWMutex
}

var (
	defaultManager *Manager
	once           sync.Once
)

// DefaultConfigPaths are the default locations to search for stacks.yaml
var DefaultConfigPaths = []string{
	"/etc/containarium/stacks.yaml",
	"./configs/stacks.yaml",
	"./stacks.yaml",
}

// New creates a new stack manager
func New() *Manager {
	return &Manager{}
}

// GetDefault returns the default stack manager (singleton)
func GetDefault() *Manager {
	once.Do(func() {
		defaultManager = New()
		// Try to load from default paths
		for _, path := range DefaultConfigPaths {
			if err := defaultManager.LoadFromFile(path); err == nil {
				return
			}
		}
		// If no file found, load embedded default
		_ = defaultManager.LoadEmbedded()
	})
	return defaultManager
}

// LoadFromFile loads stack configuration from a YAML file
func (m *Manager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read stacks file: %w", err)
	}

	return m.LoadFromBytes(data)
}

// LoadEmbedded loads the embedded default stacks configuration
func (m *Manager) LoadEmbedded() error {
	data, err := embeddedFS.ReadFile("stacks.yaml")
	if err != nil {
		return fmt.Errorf("failed to read embedded stacks: %w", err)
	}
	return m.LoadFromBytes(data)
}

// LoadFromBytes loads stack configuration from YAML bytes
func (m *Manager) LoadFromBytes(data []byte) error {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse stacks YAML: %w", err)
	}

	m.mu.Lock()
	m.config = config
	m.mu.Unlock()

	return nil
}

// GetStack returns a stack by ID
func (m *Manager) GetStack(id string) (*Stack, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, stack := range m.config.Stacks {
		if stack.ID == id {
			return &stack, nil
		}
	}

	return nil, fmt.Errorf("stack not found: %s", id)
}

// GetAllStacks returns all available stacks
func (m *Manager) GetAllStacks() []Stack {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Stack, len(m.config.Stacks))
	copy(result, m.config.Stacks)
	return result
}

// GetStackIDs returns all available stack IDs
func (m *Manager) GetStackIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, len(m.config.Stacks))
	for i, stack := range m.config.Stacks {
		ids[i] = stack.ID
	}
	return ids
}

// ValidateStackID checks if a stack ID is valid
func (m *Manager) ValidateStackID(id string) bool {
	if id == "" {
		return true // Empty is valid (no stack selected)
	}
	_, err := m.GetStack(id)
	return err == nil
}

// GetPackagesForStack returns the packages needed for a stack
func (m *Manager) GetPackagesForStack(id string) ([]string, error) {
	stack, err := m.GetStack(id)
	if err != nil {
		return nil, err
	}
	return stack.Packages, nil
}

// GetPreInstallCommands returns the pre-install commands for a stack (run as root before apt-get install)
func (m *Manager) GetPreInstallCommands(id string) ([]string, error) {
	stack, err := m.GetStack(id)
	if err != nil {
		return nil, err
	}
	return stack.PreInstall, nil
}

// GetPostInstallCommands returns the post-install commands for a stack
func (m *Manager) GetPostInstallCommands(id string) ([]string, error) {
	stack, err := m.GetStack(id)
	if err != nil {
		return nil, err
	}
	return stack.PostInstall, nil
}

// GetBaseScript returns a base script by ID
func (m *Manager) GetBaseScript(id string) (*Stack, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, bs := range m.config.BaseScripts {
		if bs.ID == id {
			return &bs, nil
		}
	}

	return nil, fmt.Errorf("base script not found: %s", id)
}

// GetAllBaseScripts returns all base scripts
func (m *Manager) GetAllBaseScripts() []Stack {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Stack, len(m.config.BaseScripts))
	copy(result, m.config.BaseScripts)
	return result
}

// GetStackOrBaseScript looks up an ID in both stacks and base_scripts.
// Returns (stack, isBaseScript, error).
func (m *Manager) GetStackOrBaseScript(id string) (*Stack, bool, error) {
	if s, err := m.GetStack(id); err == nil {
		return s, false, nil
	}
	if s, err := m.GetBaseScript(id); err == nil {
		return s, true, nil
	}
	return nil, false, fmt.Errorf("stack or base script not found: %s", id)
}
