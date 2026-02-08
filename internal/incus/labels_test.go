package incus

import (
	"testing"
)

func TestExtractLabelsFromConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]string
		wantLabels map[string]string
	}{
		{
			name:       "empty config",
			config:     map[string]string{},
			wantLabels: map[string]string{},
		},
		{
			name: "config without labels",
			config: map[string]string{
				"limits.cpu":    "4",
				"limits.memory": "8GB",
			},
			wantLabels: map[string]string{},
		},
		{
			name: "config with single label",
			config: map[string]string{
				"limits.cpu":            "4",
				"user.containarium.label.team": "backend",
			},
			wantLabels: map[string]string{
				"team": "backend",
			},
		},
		{
			name: "config with multiple labels",
			config: map[string]string{
				"limits.cpu":                "4",
				"user.containarium.label.team":     "backend",
				"user.containarium.label.project":  "api",
				"user.containarium.label.env":      "production",
				"user.containarium.label.owner":    "alice",
			},
			wantLabels: map[string]string{
				"team":    "backend",
				"project": "api",
				"env":     "production",
				"owner":   "alice",
			},
		},
		{
			name: "label with special characters in value",
			config: map[string]string{
				"user.containarium.label.description": "Production API Server v2.0",
				"user.containarium.label.url":         "https://example.com/api",
			},
			wantLabels: map[string]string{
				"description": "Production API Server v2.0",
				"url":         "https://example.com/api",
			},
		},
		{
			name: "label with empty value",
			config: map[string]string{
				"user.containarium.label.empty": "",
			},
			wantLabels: map[string]string{
				"empty": "",
			},
		},
		{
			name: "similar prefix but not a label",
			config: map[string]string{
				"containarium.labels":          "not a label",
				"user.containarium.label.real":      "label",
				"containarium.labelconfig":     "also not a label",
			},
			wantLabels: map[string]string{
				"real": "label",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLabelsFromConfig(tt.config)

			if len(got) != len(tt.wantLabels) {
				t.Errorf("extractLabelsFromConfig() returned %d labels, want %d", len(got), len(tt.wantLabels))
				return
			}

			for key, wantValue := range tt.wantLabels {
				if gotValue, ok := got[key]; !ok {
					t.Errorf("extractLabelsFromConfig() missing label %q", key)
				} else if gotValue != wantValue {
					t.Errorf("extractLabelsFromConfig() label %q = %q, want %q", key, gotValue, wantValue)
				}
			}
		})
	}
}

func TestMatchLabels(t *testing.T) {
	tests := []struct {
		name            string
		containerLabels map[string]string
		filter          map[string]string
		wantMatch       bool
	}{
		{
			name:            "empty filter matches everything",
			containerLabels: map[string]string{"team": "backend"},
			filter:          map[string]string{},
			wantMatch:       true,
		},
		{
			name:            "empty labels with empty filter",
			containerLabels: map[string]string{},
			filter:          map[string]string{},
			wantMatch:       true,
		},
		{
			name:            "empty labels with non-empty filter",
			containerLabels: map[string]string{},
			filter:          map[string]string{"team": "backend"},
			wantMatch:       false,
		},
		{
			name:            "exact match single label",
			containerLabels: map[string]string{"team": "backend"},
			filter:          map[string]string{"team": "backend"},
			wantMatch:       true,
		},
		{
			name:            "mismatch single label",
			containerLabels: map[string]string{"team": "backend"},
			filter:          map[string]string{"team": "frontend"},
			wantMatch:       false,
		},
		{
			name:            "filter with missing label",
			containerLabels: map[string]string{"team": "backend"},
			filter:          map[string]string{"project": "api"},
			wantMatch:       false,
		},
		{
			name:            "multiple labels all match",
			containerLabels: map[string]string{"team": "backend", "env": "prod", "owner": "alice"},
			filter:          map[string]string{"team": "backend", "env": "prod"},
			wantMatch:       true,
		},
		{
			name:            "multiple labels partial mismatch",
			containerLabels: map[string]string{"team": "backend", "env": "prod", "owner": "alice"},
			filter:          map[string]string{"team": "backend", "env": "staging"},
			wantMatch:       false,
		},
		{
			name:            "container has more labels than filter",
			containerLabels: map[string]string{"team": "backend", "env": "prod", "owner": "alice", "version": "v2"},
			filter:          map[string]string{"team": "backend"},
			wantMatch:       true,
		},
		{
			name:            "filter has more labels than container",
			containerLabels: map[string]string{"team": "backend"},
			filter:          map[string]string{"team": "backend", "env": "prod"},
			wantMatch:       false,
		},
		{
			name:            "nil container labels with filter",
			containerLabels: nil,
			filter:          map[string]string{"team": "backend"},
			wantMatch:       false,
		},
		{
			name:            "nil container labels with empty filter",
			containerLabels: nil,
			filter:          map[string]string{},
			wantMatch:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchLabels(tt.containerLabels, tt.filter)
			if got != tt.wantMatch {
				t.Errorf("MatchLabels() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestLabelPrefix(t *testing.T) {
	// Verify the constant is as expected
	// Note: Incus requires user-defined config keys to use the "user." prefix
	expected := "user.containarium.label."
	if LabelPrefix != expected {
		t.Errorf("LabelPrefix = %q, want %q", LabelPrefix, expected)
	}
}

// Benchmark tests
func BenchmarkExtractLabelsFromConfig(b *testing.B) {
	config := map[string]string{
		"limits.cpu":               "4",
		"limits.memory":            "8GB",
		"security.nesting":         "true",
		"user.containarium.label.team":    "backend",
		"user.containarium.label.project": "api",
		"user.containarium.label.env":     "production",
		"user.containarium.label.owner":   "alice",
		"user.containarium.label.version": "v2.1.0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractLabelsFromConfig(config)
	}
}

func BenchmarkMatchLabels(b *testing.B) {
	containerLabels := map[string]string{
		"team":    "backend",
		"project": "api",
		"env":     "production",
		"owner":   "alice",
		"version": "v2.1.0",
	}
	filter := map[string]string{
		"team": "backend",
		"env":  "production",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatchLabels(containerLabels, filter)
	}
}
