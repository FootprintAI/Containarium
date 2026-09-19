package cmd

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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
