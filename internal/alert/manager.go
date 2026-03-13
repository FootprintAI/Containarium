package alert

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/footprintai/containarium/internal/incus"
)

// Manager handles syncing alert rules from the database to vmalert inside
// the VictoriaMetrics container.
type Manager struct {
	store         *Store
	incusClient   *incus.Client
	containerName string
}

// NewManager creates a new alert rules manager
func NewManager(store *Store, incusClient *incus.Client, containerName string) *Manager {
	return &Manager{
		store:         store,
		incusClient:   incusClient,
		containerName: containerName,
	}
}

// SyncRules reads all enabled rules from the database, generates a YAML file,
// writes it to the container, and reloads vmalert.
func (m *Manager) SyncRules(ctx context.Context) error {
	rules, err := m.store.ListEnabled(ctx)
	if err != nil {
		return fmt.Errorf("failed to list enabled rules: %w", err)
	}

	yaml := generateRulesYAML(rules)

	// Write custom rules file
	if err := m.incusClient.WriteFile(
		m.containerName,
		"/etc/vmalert/rules/custom.yml",
		[]byte(yaml),
		"0644",
	); err != nil {
		return fmt.Errorf("failed to write custom rules: %w", err)
	}

	// Reload vmalert
	if err := m.incusClient.Exec(m.containerName, []string{
		"curl", "-sf", "-X", "POST", "http://localhost:8880/-/reload",
	}); err != nil {
		log.Printf("Warning: vmalert reload returned error (may still succeed): %v", err)
	}

	log.Printf("Synced %d custom alert rules to vmalert", len(rules))
	return nil
}

// generateRulesYAML converts alert rules to vmalert-compatible YAML
func generateRulesYAML(rules []*AlertRule) string {
	if len(rules) == 0 {
		return "groups: []\n"
	}

	var b strings.Builder
	b.WriteString("groups:\n")
	b.WriteString("  - name: custom_alerts\n")
	b.WriteString("    interval: 30s\n")
	b.WriteString("    rules:\n")

	for _, rule := range rules {
		b.WriteString(fmt.Sprintf("      - alert: %s\n", sanitizeAlertName(rule.Name)))
		b.WriteString(fmt.Sprintf("        expr: %s\n", rule.Expr))
		if rule.Duration != "" {
			b.WriteString(fmt.Sprintf("        for: %s\n", rule.Duration))
		}

		// Labels
		b.WriteString("        labels:\n")
		b.WriteString(fmt.Sprintf("          severity: %s\n", rule.Severity))
		b.WriteString("          source: custom\n")
		b.WriteString(fmt.Sprintf("          rule_id: %s\n", rule.ID))
		for k, v := range rule.Labels {
			b.WriteString(fmt.Sprintf("          %s: %q\n", k, v))
		}

		// Annotations
		if rule.Description != "" || len(rule.Annotations) > 0 {
			b.WriteString("        annotations:\n")
			if rule.Description != "" {
				b.WriteString(fmt.Sprintf("          description: %q\n", rule.Description))
			}
			for k, v := range rule.Annotations {
				b.WriteString(fmt.Sprintf("          %s: %q\n", k, v))
			}
		}
	}

	return b.String()
}

// sanitizeAlertName converts a human-readable name to a valid alert name
// (alphanumeric + underscores only)
func sanitizeAlertName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else if c == ' ' || c == '-' {
			b.WriteRune('_')
		}
	}
	result := b.String()
	if result == "" {
		return "unnamed_alert"
	}
	return result
}
