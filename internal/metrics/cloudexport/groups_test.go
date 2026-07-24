package cloudexport

import (
	"reflect"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestNormalizeGroups pins the backward-compatibility rule at the heart
// of #1081: an absent/empty (or all-UNSPECIFIED) groups list resolves to
// [HOST] — exactly the v0.60.0 host-only behavior a persisted config
// resumes into — and any explicit list is deduped and ordered so the
// persisted form and the golden series set are deterministic.
func TestNormalizeGroups(t *testing.T) {
	host := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST
	container := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	unspecified := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_UNSPECIFIED

	tests := []struct {
		name string
		in   []pb.CloudMetricsGroup
		want []pb.CloudMetricsGroup
	}{
		{"nil defaults to host", nil, []pb.CloudMetricsGroup{host}},
		{"empty defaults to host", []pb.CloudMetricsGroup{}, []pb.CloudMetricsGroup{host}},
		{"unspecified-only defaults to host", []pb.CloudMetricsGroup{unspecified}, []pb.CloudMetricsGroup{host}},
		{"host stays host", []pb.CloudMetricsGroup{host}, []pb.CloudMetricsGroup{host}},
		{"platform alone", []pb.CloudMetricsGroup{platform}, []pb.CloudMetricsGroup{platform}},
		{"host and platform", []pb.CloudMetricsGroup{host, platform}, []pb.CloudMetricsGroup{host, platform}},
		{"reordered is sorted", []pb.CloudMetricsGroup{platform, host}, []pb.CloudMetricsGroup{host, platform}},
		{"duplicates collapse", []pb.CloudMetricsGroup{host, host}, []pb.CloudMetricsGroup{host}},
		{"unspecified dropped from mix", []pb.CloudMetricsGroup{host, unspecified, platform}, []pb.CloudMetricsGroup{host, platform}},
		{"all three sorted", []pb.CloudMetricsGroup{container, platform, host}, []pb.CloudMetricsGroup{host, container, platform}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeGroups(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NormalizeGroups(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidateGroups pins the server-side guard: an explicit list may not
// carry UNSPECIFIED or an out-of-range value (those are client errors),
// while an empty list is valid because it means "default to host".
func TestValidateGroups(t *testing.T) {
	host := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST
	container := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	unspecified := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_UNSPECIFIED

	tests := []struct {
		name    string
		in      []pb.CloudMetricsGroup
		wantErr bool
	}{
		{"nil is valid", nil, false},
		{"empty is valid", []pb.CloudMetricsGroup{}, false},
		{"host is valid", []pb.CloudMetricsGroup{host}, false},
		{"all three valid", []pb.CloudMetricsGroup{host, container, platform}, false},
		{"unspecified alone rejected", []pb.CloudMetricsGroup{unspecified}, true},
		{"unspecified in mix rejected", []pb.CloudMetricsGroup{host, unspecified}, true},
		{"out-of-range rejected", []pb.CloudMetricsGroup{pb.CloudMetricsGroup(99)}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGroups(tc.in)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateGroups(%v) = nil, want error", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateGroups(%v) = %v, want nil", tc.in, err)
			}
		})
	}
}
