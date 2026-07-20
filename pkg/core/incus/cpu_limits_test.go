package incus

import (
	"strings"
	"testing"
)

func TestParseCPULimit(t *testing.T) {
	tests := []struct {
		name          string
		cpu           string
		wantCount     string
		wantAllowance string
		wantErr       bool
	}{
		{name: "empty", cpu: "", wantCount: "", wantAllowance: ""},
		{name: "single core", cpu: "1", wantCount: "1", wantAllowance: "100ms/100ms"},
		{name: "multiple cores", cpu: "4", wantCount: "4", wantAllowance: "400ms/100ms"},
		{name: "whole host", cpu: "8", wantCount: "8", wantAllowance: "800ms/100ms"},
		{name: "cpu range", cpu: "0-3", wantCount: "0-3"},
		{name: "cpu set", cpu: "0,2-4", wantCount: "0,2-4"},
		{name: "millicpu quarter core", cpu: "250m", wantCount: "1", wantAllowance: "25ms/100ms"},
		{name: "millicpu half core", cpu: "500m", wantCount: "1", wantAllowance: "50ms/100ms"},
		{name: "millicpu whole core", cpu: "1000m", wantCount: "1", wantAllowance: "100ms/100ms"},
		{name: "millicpu one and a half", cpu: "1500m", wantCount: "2", wantAllowance: "150ms/100ms"},
		{name: "decimal quarter core", cpu: "0.25", wantCount: "1", wantAllowance: "25ms/100ms"},
		{name: "decimal whole core", cpu: "2.0", wantCount: "2", wantAllowance: "200ms/100ms"},
		{name: "decimal one and a half", cpu: "1.5", wantCount: "2", wantAllowance: "150ms/100ms"},
		{name: "decimal two and a half", cpu: "2.5", wantCount: "3", wantAllowance: "250ms/100ms"},
		{name: "whitespace trimmed", cpu: "  250m  ", wantCount: "1", wantAllowance: "25ms/100ms"},
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

// TestCPUAllowanceIsAHardQuota is the point of #1034 and the one property
// that must not silently regress: Incus reads a PERCENTAGE allowance as a
// soft scheduler share (cpu.max stays "max", so an idle host lets one tenant
// take all of it) and the ms/ms form as a hard CFS quota. Emitting a
// percentage would look correct in `incus config show` while enforcing
// nothing — exactly the failure #1030 shipped with.
func TestCPUAllowanceIsAHardQuota(t *testing.T) {
	for _, in := range []string{"1", "4", "8", "250m", "1500m", "0.25", "2.5"} {
		cl, err := parseCPULimit(in)
		if err != nil {
			t.Fatalf("parseCPULimit(%q): %v", in, err)
		}
		if strings.HasSuffix(cl.Allowance, "%") {
			t.Errorf("parseCPULimit(%q).Allowance = %q — a percentage is a SOFT share and does not throttle", in, cl.Allowance)
		}
		if !strings.HasSuffix(cl.Allowance, "ms/100ms") {
			t.Errorf("parseCPULimit(%q).Allowance = %q, want the hard-quota form <N>ms/100ms", in, cl.Allowance)
		}
	}
}

// TestCPUQuotaFloor: a request finer than the 1ms quota granularity must
// round up to 1ms, never to 0 — Incus rejects a zero quota, and a container
// that may never be scheduled is never what the caller asked for.
func TestCPUQuotaFloor(t *testing.T) {
	cl, err := parseCPULimit("1m") // 0.001 core → 0.1ms of quota
	if err != nil {
		t.Fatalf("parseCPULimit(\"1m\"): %v", err)
	}
	if cl.Allowance != "1ms/100ms" {
		t.Fatalf("parseCPULimit(\"1m\").Allowance = %q, want %q", cl.Allowance, "1ms/100ms")
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
		{name: "quota quarter core", config: map[string]string{"limits.cpu.allowance": "25ms/100ms"}, want: "250m"},
		{name: "quota half core", config: map[string]string{"limits.cpu.allowance": "50ms/100ms"}, want: "500m"},
		{name: "quota over one core", config: map[string]string{"limits.cpu.allowance": "150ms/100ms"}, want: "1500m"},
		{
			name:   "allowance wins over limits.cpu (fractional request sets both)",
			config: map[string]string{"limits.cpu": "1", "limits.cpu.allowance": "25ms/100ms"},
			want:   "250m",
		},
		{name: "empty limits.cpu falls through to allowance", config: map[string]string{"limits.cpu": "", "limits.cpu.allowance": "25ms/100ms"}, want: "250m"},
		{name: "empty allowance falls through to limits.cpu", config: map[string]string{"limits.cpu": "4", "limits.cpu.allowance": ""}, want: "4"},
		{
			name:   "whole-core quota formats as plain core count, not millicpu (#1029)",
			config: map[string]string{"limits.cpu": "8", "limits.cpu.allowance": "800ms/100ms"},
			want:   "8",
		},
		{
			name:   "single-core quota formats as plain core count",
			config: map[string]string{"limits.cpu": "1", "limits.cpu.allowance": "100ms/100ms"},
			want:   "1",
		},

		// Containers created before #1034 carry the percentage form; a daemon
		// upgrade must keep displaying their request correctly rather than
		// dumping the raw Incus value at the caller.
		{name: "legacy percentage fractional", config: map[string]string{"limits.cpu.allowance": "25%"}, want: "250m"},
		{name: "legacy percentage whole core", config: map[string]string{"limits.cpu": "4", "limits.cpu.allowance": "400%"}, want: "4"},

		// An operator-set allowance against a non-default period is still a
		// valid quota and resolves to its true core count.
		{name: "non-default period", config: map[string]string{"limits.cpu.allowance": "100ms/200ms"}, want: "500m"},

		// Unparseable allowances pass through untouched — better to show the
		// raw Incus value than to invent a number.
		{name: "garbage allowance passthrough", config: map[string]string{"limits.cpu.allowance": "sometimes"}, want: "sometimes"},
		{name: "zero period passthrough", config: map[string]string{"limits.cpu.allowance": "100ms/0ms"}, want: "100ms/0ms"},
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
