package ostype

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestIsWindows(t *testing.T) {
	tests := []struct {
		name   string
		osType pb.OSType
		want   bool
	}{
		{"unspecified", pb.OSType_OS_TYPE_UNSPECIFIED, false},
		{"ubuntu", pb.OSType_OS_TYPE_UBUNTU_2404, false},
		{"rocky", pb.OSType_OS_TYPE_ROCKY_9, false},
		{"rhel", pb.OSType_OS_TYPE_RHEL_9, false},
		{"windows 2022", pb.OSType_OS_TYPE_WINDOWS_2022, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsWindows(tt.osType); got != tt.want {
				t.Errorf("IsWindows(%v) = %v, want %v", tt.osType, got, tt.want)
			}
		})
	}
}

func TestImageForOSType_Windows(t *testing.T) {
	got := ImageForOSType(pb.OSType_OS_TYPE_WINDOWS_2022)
	want := "local:windows-server-2022"
	if got != want {
		t.Errorf("ImageForOSType(WINDOWS_2022) = %q, want %q", got, want)
	}
}

func TestFamilyForOSType_Windows(t *testing.T) {
	got := FamilyForOSType(pb.OSType_OS_TYPE_WINDOWS_2022)
	if got != Windows {
		t.Errorf("FamilyForOSType(WINDOWS_2022) = %q, want %q", got, Windows)
	}
}

func TestLabelValue_Windows(t *testing.T) {
	got := LabelValue(pb.OSType_OS_TYPE_WINDOWS_2022)
	want := "windows_2022"
	if got != want {
		t.Errorf("LabelValue(WINDOWS_2022) = %q, want %q", got, want)
	}
}

func TestFamilyFromLabel_Windows(t *testing.T) {
	got := FamilyFromLabel("windows_2022")
	if got != Windows {
		t.Errorf("FamilyFromLabel(\"windows_2022\") = %q, want %q", got, Windows)
	}
}

func TestOSTypeFromLabel_Windows(t *testing.T) {
	got := OSTypeFromLabel("windows_2022")
	want := pb.OSType_OS_TYPE_WINDOWS_2022
	if got != want {
		t.Errorf("OSTypeFromLabel(\"windows_2022\") = %v, want %v", got, want)
	}
}

func TestOSTypeFromString_Windows(t *testing.T) {
	tests := []struct {
		input string
		want  pb.OSType
	}{
		{"windows2022", pb.OSType_OS_TYPE_WINDOWS_2022},
		{"windows-2022", pb.OSType_OS_TYPE_WINDOWS_2022},
		{"win2022", pb.OSType_OS_TYPE_WINDOWS_2022},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := OSTypeFromString(tt.input); got != tt.want {
				t.Errorf("OSTypeFromString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestRoundTrip verifies label serialization round-trips for all OS types.
func TestRoundTrip(t *testing.T) {
	osTypes := []pb.OSType{
		pb.OSType_OS_TYPE_UBUNTU_2404,
		pb.OSType_OS_TYPE_ROCKY_9,
		pb.OSType_OS_TYPE_RHEL_9,
		pb.OSType_OS_TYPE_WINDOWS_2022,
	}
	for _, osType := range osTypes {
		label := LabelValue(osType)
		got := OSTypeFromLabel(label)
		if got != osType {
			t.Errorf("round-trip failed: OSType %v -> label %q -> OSType %v", osType, label, got)
		}
	}
}

// TestFamilyConsistency verifies FamilyForOSType and FamilyFromLabel agree.
func TestFamilyConsistency(t *testing.T) {
	osTypes := []pb.OSType{
		pb.OSType_OS_TYPE_UBUNTU_2404,
		pb.OSType_OS_TYPE_ROCKY_9,
		pb.OSType_OS_TYPE_RHEL_9,
		pb.OSType_OS_TYPE_WINDOWS_2022,
	}
	for _, osType := range osTypes {
		label := LabelValue(osType)
		fromEnum := FamilyForOSType(osType)
		fromLabel := FamilyFromLabel(label)
		if fromEnum != fromLabel {
			t.Errorf("family mismatch for %v: FamilyForOSType=%q, FamilyFromLabel(%q)=%q",
				osType, fromEnum, label, fromLabel)
		}
	}
}
