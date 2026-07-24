package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestParseMetricsExportProvider covers --provider flag parsing:
// happy path (gcp), the reserved-but-known aws value (passed through
// so the server's Unimplemented is the single source of truth), and
// the client-side-only rejections (empty, typo).
func TestParseMetricsExportProvider(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      pb.CloudMetricsProvider
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "gcp",
			input: "gcp",
			want:  pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
		},
		{
			name:  "GCP uppercase is case-insensitive",
			input: "GCP",
			want:  pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
		},
		{
			name:  "  gcp  trims whitespace",
			input: "  gcp  ",
			want:  pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
		},
		{
			name:  "aws is parsed and passed through (server rejects it)",
			input: "aws",
			want:  pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_AWS,
		},
		{
			name:      "empty is required",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "unknown provider is rejected client-side",
			input:     "gpc",
			wantErr:   true,
			errSubstr: "unknown provider",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMetricsExportProvider(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMetricsExportProvider(%q) = %v, nil; want error containing %q", tc.input, got, tc.errSubstr)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseMetricsExportProvider(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestParseMetricsExportGroups covers --groups flag parsing: the empty
// case (omitted ⇒ nil ⇒ server defaults to host), each known group,
// case-insensitivity and whitespace tolerance, multi-group lists, and
// the client-side rejection of an unknown group name.
func TestParseMetricsExportGroups(t *testing.T) {
	host := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST
	container := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM

	tests := []struct {
		name      string
		input     string
		want      []pb.CloudMetricsGroup
		wantErr   bool
		errSubstr string
	}{
		{name: "empty omits (server defaults host)", input: "", want: nil},
		{name: "host", input: "host", want: []pb.CloudMetricsGroup{host}},
		{name: "container", input: "container", want: []pb.CloudMetricsGroup{container}},
		{name: "platform", input: "platform", want: []pb.CloudMetricsGroup{platform}},
		{name: "host,platform", input: "host,platform", want: []pb.CloudMetricsGroup{host, platform}},
		{name: "whitespace tolerated", input: " host , platform ", want: []pb.CloudMetricsGroup{host, platform}},
		{name: "case-insensitive", input: "HOST,Platform", want: []pb.CloudMetricsGroup{host, platform}},
		{name: "empty elements skipped", input: "host,,platform", want: []pb.CloudMetricsGroup{host, platform}},
		{name: "unknown group rejected", input: "host,bogus", wantErr: true, errSubstr: "unknown metric group"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMetricsExportGroups(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMetricsExportGroups(%q) = %v, nil; want error containing %q", tc.input, got, tc.errSubstr)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseMetricsExportGroups(%q) = %v, want %v", tc.input, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("parseMetricsExportGroups(%q)[%d] = %v, want %v", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestMetricsExportGroupsLabel(t *testing.T) {
	tests := []struct {
		name   string
		groups []pb.CloudMetricsGroup
		want   string
	}{
		{"empty is host default", nil, "host"},
		{"single", []pb.CloudMetricsGroup{pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST}, "host"},
		{
			"multi",
			[]pb.CloudMetricsGroup{
				pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST,
				pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM,
			},
			"host,platform",
		},
	}
	for _, tc := range tests {
		if got := metricsExportGroupsLabel(tc.groups); got != tc.want {
			t.Errorf("metricsExportGroupsLabel(%v) = %q, want %q", tc.groups, got, tc.want)
		}
	}
}

func TestMetricsExportProviderLabel(t *testing.T) {
	tests := []struct {
		provider pb.CloudMetricsProvider
		want     string
	}{
		{pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP, "gcp"},
		{pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_AWS, "aws"},
		{pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED, "unspecified"},
	}
	for _, tc := range tests {
		if got := metricsExportProviderLabel(tc.provider); got != tc.want {
			t.Errorf("metricsExportProviderLabel(%v) = %q, want %q", tc.provider, got, tc.want)
		}
	}
}

// TestRunMetricsExportEnable_RequiresProvider covers the "no --server,
// no --provider" client-side failure paths without touching the
// network: parseMetricsExportProvider fires before the --server check,
// so a bare `enable` with neither flag fails on the provider message.
func TestRunMetricsExportEnable_RequiresProvider(t *testing.T) {
	origProvider := metricsExportProvider
	origServer := serverAddr
	defer func() {
		metricsExportProvider = origProvider
		serverAddr = origServer
	}()

	metricsExportProvider = ""
	serverAddr = ""

	err := runMetricsExportEnable(monitoringExportEnableCmd, nil)
	if err == nil {
		t.Fatal("expected error when --provider is missing")
	}
	if !strings.Contains(err.Error(), "--provider is required") {
		t.Errorf("error = %q, want it to mention --provider", err.Error())
	}
}

// TestRunMetricsExportEnable_RequiresServer locks that a valid
// --provider still needs --server (no local fallback — mirrors
// runMonitoringToggle's rule in internal/cmd/monitoring.go).
func TestRunMetricsExportEnable_RequiresServer(t *testing.T) {
	origProvider := metricsExportProvider
	origServer := serverAddr
	defer func() {
		metricsExportProvider = origProvider
		serverAddr = origServer
	}()

	metricsExportProvider = "gcp"
	serverAddr = ""

	err := runMetricsExportEnable(monitoringExportEnableCmd, nil)
	if err == nil {
		t.Fatal("expected error when --server is missing")
	}
	if !strings.Contains(err.Error(), "--server is required") {
		t.Errorf("error = %q, want it to mention --server", err.Error())
	}
}

func TestRunMetricsExportDisable_RequiresServer(t *testing.T) {
	origServer := serverAddr
	defer func() { serverAddr = origServer }()
	serverAddr = ""

	err := runMetricsExportDisable(monitoringExportDisableCmd, nil)
	if err == nil {
		t.Fatal("expected error when --server is missing")
	}
	if !strings.Contains(err.Error(), "--server is required") {
		t.Errorf("error = %q, want it to mention --server", err.Error())
	}
}

func TestRunMetricsExportStatus_RequiresServer(t *testing.T) {
	origServer := serverAddr
	defer func() { serverAddr = origServer }()
	serverAddr = ""

	err := runMetricsExportStatus(monitoringExportStatusCmd, nil)
	if err == nil {
		t.Fatal("expected error when --server is missing")
	}
	if !strings.Contains(err.Error(), "--server is required") {
		t.Errorf("error = %q, want it to mention --server", err.Error())
	}
}
