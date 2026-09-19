package tracker

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestProviderToString(t *testing.T) {
	tests := []struct {
		in      pb.TrackerProvider
		want    string
		wantErr bool
	}{
		{pb.TrackerProvider_TRACKER_PROVIDER_GITHUB, "github", false},
		{pb.TrackerProvider_TRACKER_PROVIDER_GITLAB, "gitlab", false},
		{pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED, "", true},
	}
	for _, tc := range tests {
		got, err := providerToString(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("providerToString(%v) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("providerToString(%v) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("providerToString(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProviderRoundTrip(t *testing.T) {
	for _, p := range []pb.TrackerProvider{
		pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		pb.TrackerProvider_TRACKER_PROVIDER_GITLAB,
	} {
		s, err := providerToString(p)
		if err != nil {
			t.Fatalf("providerToString(%v): %v", p, err)
		}
		if got := providerFromString(s); got != p {
			t.Errorf("round trip %v -> %q -> %v", p, s, got)
		}
	}
}

func TestProviderFromString_Unknown(t *testing.T) {
	if got := providerFromString("bitbucket"); got != pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED {
		t.Errorf("providerFromString(%q) = %v, want UNSPECIFIED", "bitbucket", got)
	}
}
