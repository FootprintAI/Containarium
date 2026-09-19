package cmd

import (
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestParseTrackerProvider(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    pb.TrackerProvider
		wantErr bool
	}{
		{"github", "github", pb.TrackerProvider_TRACKER_PROVIDER_GITHUB, false},
		{"gitlab", "gitlab", pb.TrackerProvider_TRACKER_PROVIDER_GITLAB, false},
		{"uppercase GITHUB", "GITHUB", pb.TrackerProvider_TRACKER_PROVIDER_GITHUB, false},
		{"padded", "  gitlab  ", pb.TrackerProvider_TRACKER_PROVIDER_GITLAB, false},
		// Unlike --protocol elsewhere in this package, empty is an error
		// here — provider is never inferred or defaulted.
		{"empty is an error, not a default", "", pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED, true},
		{"invalid", "bitbucket", pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTrackerProvider(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseTrackerProvider(%q) = %v; want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestTrackerProviderLabel(t *testing.T) {
	tests := []struct {
		in   pb.TrackerProvider
		want string
	}{
		{pb.TrackerProvider_TRACKER_PROVIDER_GITHUB, "github"},
		{pb.TrackerProvider_TRACKER_PROVIDER_GITLAB, "gitlab"},
		{pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED, "unspecified"},
	}
	for _, tt := range tests {
		if got := trackerProviderLabel(tt.in); got != tt.want {
			t.Errorf("trackerProviderLabel(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTrackerBreadthLabel(t *testing.T) {
	tests := []struct {
		in   pb.TrackerCredentialBreadth
		want string
	}{
		{pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_PREFERRED, "preferred"},
		{pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_BROAD, "broad"},
		{pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_UNSPECIFIED, "unknown"},
	}
	for _, tt := range tests {
		if got := trackerBreadthLabel(tt.in); got != tt.want {
			t.Errorf("trackerBreadthLabel(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPrintTrackerStatus_Unreachable_OmitsCredentialDetails(t *testing.T) {
	out := captureStdout(t, func() {
		printTrackerStatus(&pb.GetTrackerStatusResponse{
			Reachable: false,
			Detail:    "tracker: upstream unreachable: dial tcp: connection refused",
		})
	})
	if !strings.Contains(out, "reachable:        false") {
		t.Errorf("output = %q, want it to report reachable: false", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Errorf("output = %q, want the detail message", out)
	}
	if strings.Contains(out, "breadth:") {
		t.Errorf("output = %q, want no breadth line when unreachable", out)
	}
}

func TestPrintTrackerStatus_BroadBreadth_WarnsWithProviderName(t *testing.T) {
	out := captureStdout(t, func() {
		printTrackerStatus(&pb.GetTrackerStatusResponse{
			Reachable:         true,
			CredentialValid:   true,
			CredentialBreadth: pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_BROAD,
			CredentialScopes:  []string{"repo"},
			Connection:        &pb.TrackerConnection{Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB},
		})
	})
	if !strings.Contains(out, "breadth:          broad") {
		t.Errorf("output = %q, want breadth: broad", out)
	}
	if !strings.Contains(out, "⚠") || !strings.Contains(out, "github") {
		t.Errorf("output = %q, want a warning naming the provider", out)
	}
}

func TestPrintTrackerStatus_PreferredBreadth_NoWarning(t *testing.T) {
	expiry := time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)
	out := captureStdout(t, func() {
		printTrackerStatus(&pb.GetTrackerStatusResponse{
			Reachable:           true,
			CredentialValid:     true,
			CredentialBreadth:   pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_PREFERRED,
			CredentialExpiresAt: timestamppb.New(expiry),
		})
	})
	if strings.Contains(out, "⚠") {
		t.Errorf("output = %q, want no warning for a preferred credential", out)
	}
	if !strings.Contains(out, "2027-05-01") {
		t.Errorf("output = %q, want the expiry date", out)
	}
}

func TestPrintTrackerStatus_CredentialInvalid_ShowsDetail(t *testing.T) {
	out := captureStdout(t, func() {
		printTrackerStatus(&pb.GetTrackerStatusResponse{
			Reachable:       true,
			CredentialValid: false,
			Detail:          "tracker: credential rejected by provider: HTTP 401",
		})
	})
	if !strings.Contains(out, "credential valid: false") {
		t.Errorf("output = %q, want credential valid: false", out)
	}
	if !strings.Contains(out, "HTTP 401") {
		t.Errorf("output = %q, want the detail message", out)
	}
}
