package incus

import "testing"

func TestParseCPULimit(t *testing.T) {
	tests := []struct {
		name          string
		cpu           string
		wantCount     string
		wantAllowance string
		wantErr       bool
	}{
		{name: "empty", cpu: "", wantCount: "", wantAllowance: ""},
		{name: "single core", cpu: "1", wantCount: "1", wantAllowance: "100%"},
		{name: "multiple cores", cpu: "4", wantCount: "4", wantAllowance: "400%"},
		{name: "whole host", cpu: "8", wantCount: "8", wantAllowance: "800%"},
		{name: "cpu range", cpu: "0-3", wantCount: "0-3"},
		{name: "cpu set", cpu: "0,2-4", wantCount: "0,2-4"},
		{name: "millicpu quarter core", cpu: "250m", wantCount: "1", wantAllowance: "25%"},
		{name: "millicpu half core", cpu: "500m", wantCount: "1", wantAllowance: "50%"},
		{name: "millicpu whole core", cpu: "1000m", wantCount: "1", wantAllowance: "100%"},
		{name: "millicpu one and a half", cpu: "1500m", wantCount: "2", wantAllowance: "150%"},
		{name: "decimal quarter core", cpu: "0.25", wantCount: "1", wantAllowance: "25%"},
		{name: "decimal whole core", cpu: "2.0", wantCount: "2", wantAllowance: "200%"},
		{name: "decimal one and a half", cpu: "1.5", wantCount: "2", wantAllowance: "150%"},
		{name: "decimal two and a half", cpu: "2.5", wantCount: "3", wantAllowance: "250%"},
		{name: "whitespace trimmed", cpu: "  250m  ", wantCount: "1", wantAllowance: "25%"},
		{name: "invalid millicpu", cpu: "abcm", wantErr: true},
		{name: "invalid decimal", cpu: "xyz", wantErr: true},
		{name: "negative", cpu: "-1.5", wantErr: true},
		{name: "zero", cpu: "0", wantErr: true},
		{name: "zero millicpu", cpu: "0m", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCPULimit(tt.cpu)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseCPULimit(%q) = %+v, want error", tt.cpu, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCPULimit(%q) unexpected error: %v", tt.cpu, err)
			}
			if got.Count != tt.wantCount {
				t.Errorf("parseCPULimit(%q).Count = %q, want %q", tt.cpu, got.Count, tt.wantCount)
			}
			if got.Allowance != tt.wantAllowance {
				t.Errorf("parseCPULimit(%q).Allowance = %q, want %q", tt.cpu, got.Allowance, tt.wantAllowance)
			}
		})
	}
}

func TestParseCPULimitNegativeMillicpu(t *testing.T) {
	if _, err := parseCPULimit("-250m"); err == nil {
		t.Fatal("parseCPULimit(\"-250m\") = nil error, want error")
	}
}

func TestFormatCPULimitFromConfig(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		want   string
	}{
		{name: "no limits", config: map[string]string{}, want: ""},
		{name: "whole core, no allowance (pre-#1029 config)", config: map[string]string{"limits.cpu": "4"}, want: "4"},
		{name: "cpu set", config: map[string]string{"limits.cpu": "0-3"}, want: "0-3"},
		{name: "allowance percentage", config: map[string]string{"limits.cpu.allowance": "25%"}, want: "250m"},
		{name: "allowance half", config: map[string]string{"limits.cpu.allowance": "50%"}, want: "500m"},
		{name: "allowance over one core", config: map[string]string{"limits.cpu.allowance": "150%"}, want: "1500m"},
		{name: "time slice allowance passthrough", config: map[string]string{"limits.cpu.allowance": "25ms/100ms"}, want: "25ms/100ms"},
		{
			name:   "allowance wins over limits.cpu (fractional request sets both)",
			config: map[string]string{"limits.cpu": "1", "limits.cpu.allowance": "25%"},
			want:   "250m",
		},
		{name: "empty limits.cpu falls through to allowance", config: map[string]string{"limits.cpu": "", "limits.cpu.allowance": "25%"}, want: "250m"},
		{name: "empty allowance falls through to limits.cpu", config: map[string]string{"limits.cpu": "4", "limits.cpu.allowance": ""}, want: "4"},
		{
			name:   "whole-core allowance formats as plain core count, not millicpu (#1029)",
			config: map[string]string{"limits.cpu": "8", "limits.cpu.allowance": "800%"},
			want:   "8",
		},
		{
			name:   "single-core allowance formats as plain core count",
			config: map[string]string{"limits.cpu": "1", "limits.cpu.allowance": "100%"},
			want:   "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatCPULimitFromConfig(tt.config); got != tt.want {
				t.Errorf("formatCPULimitFromConfig(%v) = %q, want %q", tt.config, got, tt.want)
			}
		})
	}
}

// TestCPULimitRoundTrip confirms a request survives the
// translate-then-read-back cycle as the same value: fractional requests as
// the same millicpu value, whole-core requests as the same plain core count
// (#1029 — despite now also carrying a limits.cpu.allowance).
func TestCPULimitRoundTrip(t *testing.T) {
	for _, in := range []string{"250m", "500m", "1500m", "1", "4", "8"} {
		cl, err := parseCPULimit(in)
		if err != nil {
			t.Fatalf("parseCPULimit(%q): %v", in, err)
		}
		config := map[string]string{}
		if cl.Count != "" {
			config["limits.cpu"] = cl.Count
		}
		if cl.Allowance != "" {
			config["limits.cpu.allowance"] = cl.Allowance
		}
		if got := formatCPULimitFromConfig(config); got != in {
			t.Errorf("round-trip of %q = %q, want %q", in, got, in)
		}
	}
}
